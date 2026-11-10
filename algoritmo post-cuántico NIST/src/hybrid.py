"""
Capa hibrida KEM-DEM: ML-KEM (FIPS 203) + AES-256-GCM.

Un KEM no cifra datos arbitrarios: produce una llave simetrica y un texto
cifrado de llave (ciphertext). Para cifrar un mensaje se usa el esquema
estandar KEM-DEM (Key Encapsulation Mechanism + Data Encapsulation Mechanism).

Construccion (documentada y reproducible):
    1. (ek, dk)  <- ML-KEM.KeyGen()                     [FIPS 203, Algoritmo 19]
    2. (K, c_kem) <- ML-KEM.Encaps(ek)                  [FIPS 203, Algoritmo 20]
    3. key_aes   <- HKDF-SHA256(ikm = K,
                                salt = c_kem,
                                info = "FIPS203|AES-256-GCM|v1|<param>",
                                L = 32)
    4. c_dem     <- AES-256-GCM(key_aes, nonce_aleatorio_96bits,
                                aad = cabecera || c_kem, mensaje)
    5. ML-KEM.Decaps(dk, c_kem) -> K' ; si todo es valido K' = K
       y AES-256-GCM descifra y autentica c_dem.

Justificacion normativa:
    - FIPS 203 define ML-KEM (KEM). No define cifrado de mensajes.
    - El uso de un KEM para establecer una llave y luego AES-GCM para los
      datos es la construccion hibrida recomendada por el NIST
      (SP 800-56C Rev. 2 / SP 800-227, "Recommendations for Key-
      Encapsulation Mechanisms").
    - HKDF esta definido en RFC 5869 y es el KDF por defecto en SP 800-56C.
    - AES-256-GCM esta definido en NIST SP 800-38D (96-bit nonce, 128-bit tag).

Formato del paquete (big-endian, pensado para ser explicito y auditable):

    +--------+---------+-----------+--------------+-----------+-------------+
    | "PQCH" | version | param_id  | c_kem_len    | c_kem     | nonce (12B) |
    | 4 B    | 1 B = 1 | 1 B       | 2 B          | variable  |             |
    +--------+---------+-----------+--------------+-----------+-------------+
    | AES-256-GCM ciphertext (incluye tag de 16 B al final)                  |
    +------------------------------------------------------------------------+

    param_id: 1 = ML-KEM-512, 2 = ML-KEM-768, 3 = ML-KEM-1024
    AAD = "PQCH" || version || param_id || c_kem_len || c_kem

El paquete es autocontenido: quien posee dk puede descifrarlo sin metadatos
externos. El AAD autentica la cabecera y el ciphertext KEM (evita
manipulacion del algorithm identifier / downgrade).
"""

from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ml_kem import MLKEM, MLKEMError

MAGIC = b"PQCH"
VERSION = 1
NONCE_BYTES = 12
TAG_BYTES = 16
HEADER_BYTES = 8  # magic(4) + version(1) + param_id(1) + ct_len(2)
KDF_INFO = b"FIPS203|AES-256-GCM|v1|"

PARAM_IDS = {"ML-KEM-512": 1, "ML-KEM-768": 2, "ML-KEM-1024": 3}
ID_PARAMS = {v: k for k, v in PARAM_IDS.items()}


class PQCryptoError(Exception):
    """Error base de la capa hibrida."""


class PacketError(PQCryptoError):
    """Paquete malformado (longitud, magic, version o parametro invalido)."""


class IntegrityError(PQCryptoError):
    """Fallo de autenticacion AES-GCM (tag invalido) o KEM inconsistente."""


def derive_key(kem_secret: bytes, kem_ciphertext: bytes, parameter_set: str) -> bytes:
    """Deriva la llave AES-256 con HKDF-SHA256 (RFC 5869)."""
    if len(kem_secret) != 32:
        raise PQCryptoError("el secreto KEM debe medir 32 bytes")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kem_ciphertext,
        info=KDF_INFO + parameter_set.encode("ascii"),
    )
    return hkdf.derive(kem_secret)


class HybridCipher:
    """ML-KEM + AES-256-GCM para cifrar/descifrar mensajes."""

    def __init__(self, parameter_set: str = "ML-KEM-768"):
        if parameter_set not in PARAM_IDS:
            raise PQCryptoError(
                f"parametro desconocido {parameter_set!r}; use {sorted(PARAM_IDS)}"
            )
        self.parameter_set = parameter_set
        self.param_id = PARAM_IDS[parameter_set]
        self.kem = MLKEM(parameter_set)

    # -- Paso 1: generacion de llaves -------------------------------------
    def keygen(self) -> tuple[bytes, bytes]:
        """Devuelve (ek, dk) = (llave de encapsulamiento, de desencapsulamiento)."""
        return self.kem.keygen()

    def check_ek(self, ek: bytes) -> None:
        self.kem.check_ek(ek)

    def check_dk(self, dk: bytes) -> None:
        self.kem.check_dk(dk)

    # -- Paso 2: KEM (llave + secreto compartido) --------------------------
    def encapsulate(self, ek: bytes) -> tuple[bytes, bytes]:
        """Devuelve (K, c_kem): secreto compartido de 32 B y ciphertext KEM."""
        return self.kem.encaps(ek)

    def decapsulate(self, dk: bytes, kem_ciphertext: bytes) -> bytes:
        """Recupera el secreto compartido K a partir de c_kem y dk."""
        return self.kem.decaps(dk, kem_ciphertext)

    # -- Pasos 3 y 4: DEM con AES-256-GCM ---------------------------------
    def encrypt(self, ek: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Cifra un mensaje y devuelve el paquete binario autocontenido."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise PQCryptoError("plaintext debe ser bytes")
        kem_secret, kem_ct = self.encapsulate(ek)
        if len(kem_ct) > 0xFFFF:
            raise PQCryptoError("ciphertext KEM demasiado grande para el formato")
        aes_key = derive_key(kem_secret, kem_ct, self.parameter_set)

        header = MAGIC + bytes([VERSION, self.param_id]) + struct.pack(">H", len(kem_ct))
        aad_full = header + kem_ct + aad
        nonce = os.urandom(NONCE_BYTES)
        aead_ct = AESGCM(aes_key).encrypt(nonce, bytes(plaintext), aad_full)
        return header + kem_ct + nonce + aead_ct

    def decrypt(self, dk: bytes, packet: bytes, aad: bytes = b"") -> bytes:
        """Descifra y autentica un paquete. Lanza PacketError/IntegrityError."""
        if not isinstance(packet, (bytes, bytearray)):
            raise PacketError("el paquete debe ser bytes")
        packet = bytes(packet)
        if len(packet) < HEADER_BYTES + NONCE_BYTES + TAG_BYTES:
            raise PacketError("paquete demasiado corto")
        if packet[:4] != MAGIC:
            raise PacketError("magic invalido (no es un paquete PQCH)")
        if packet[4] != VERSION:
            raise PacketError(f"version no soportada: {packet[4]}")
        param_id = packet[5]
        if param_id != self.param_id:
            raise PacketError(
                f"param_id {param_id} no coincide con la instancia {self.parameter_set}"
            )
        (kem_ct_len,) = struct.unpack(">H", packet[6:8])
        minimum = HEADER_BYTES + kem_ct_len + NONCE_BYTES + TAG_BYTES
        if kem_ct_len != self.kem.params.ct_bytes:
            raise PacketError(
                f"longitud de c_kem invalida: {kem_ct_len} (esperada {self.kem.params.ct_bytes})"
            )
        if len(packet) < minimum:
            raise PacketError(
                f"paquete truncado: {len(packet)} B (minimo {minimum} B)"
            )

        kem_ct = packet[HEADER_BYTES : HEADER_BYTES + kem_ct_len]
        nonce = packet[HEADER_BYTES + kem_ct_len : HEADER_BYTES + kem_ct_len + NONCE_BYTES]
        aead_ct = packet[HEADER_BYTES + kem_ct_len + NONCE_BYTES :]
        aad_full = packet[: HEADER_BYTES + kem_ct_len] + aad

        try:
            kem_secret = self.decapsulate(dk, kem_ct)
        except MLKEMError as exc:
            raise PacketError(str(exc)) from exc
        aes_key = derive_key(kem_secret, kem_ct, self.parameter_set)
        try:
            return AESGCM(aes_key).decrypt(nonce, aead_ct, aad_full)
        except InvalidTag as exc:
            raise IntegrityError(
                "autenticacion AES-256-GCM fallida: paquete alterado o llave incorrecta"
            ) from exc

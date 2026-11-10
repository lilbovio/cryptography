"""
ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
Implementacion en Python puro de FIPS 203 (NIST, 13 de agosto de 2024).

Referencia normativa:
    NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
    https://doi.org/10.6028/NIST.FIPS.203

El codigo sigue literalmente los algoritmos numerados del estandar:
    - Algoritmo 5:  ByteEncode_d
    - Algoritmo 6:  ByteDecode_d
    - Algoritmo 7:  SampleNTT (XOF = SHAKE128)
    - Algoritmo 8:  SamplePolyCBD_eta (PRF = SHAKE256)
    - Algoritmo 9:  NTT
    - Algoritmo 10: NTT^-1
    - Algoritmo 11: MultiplyNTTs
    - Algoritmo 12: BaseCaseMultiply
    - Algoritmo 13: K-PKE.KeyGen
    - Algoritmo 14: K-PKE.Encrypt
    - Algoritmo 15: K-PKE.Decrypt
    - Algoritmo 16: ML-KEM.KeyGen_internal
    - Algoritmo 17: ML-KEM.Encaps_internal
    - Algoritmo 18: ML-KEM.Decaps_internal
    - Algoritmo 19: ML-KEM.KeyGen
    - Algoritmo 20: ML-KEM.Encaps
    - Algoritmo 21: ML-KEM.Decaps
    - Seccion 7.2/7.3: verificacion de llaves de entrada (modulus check, hash check)

La numeracion corresponde a la version publicada de FIPS 203 (2024-08-13).

Dependencias: solo biblioteca estandar (hashlib para SHA3/SHAKE).
No se usa ninguna libreria criptografica externa para ML-KEM.

ADVERTENCIA ACADEMICA: esta implementacion es correcta respecto a los vectores
oficiales del NIST (ACVP), pero NO esta endurecida contra ataques de canal
lateral (timing/cache). No debe usarse en produccion.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Parametros globales de FIPS 203
# ---------------------------------------------------------------------------
Q = 3329          # primo del anillo R_q = Z_q[X]/(X^256 + 1)
N = 256           # grado del polinomio
ZETA = 17         # raiz 256-esima primitiva de la unidad modulo q
INV128 = 3303     # 128^{-1} mod q  (usado por NTT^-1, Algoritmo 10)


@dataclass(frozen=True)
class Params:
    """Conjunto de parametros de FIPS 203, Tabla 2."""

    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

    # --- tamanos oficiales de FIPS 203, Tabla 3 (en bytes) ---
    @property
    def ek_bytes(self) -> int:
        return 384 * self.k + 32

    @property
    def dk_bytes(self) -> int:
        return 768 * self.k + 96

    @property
    def ct_bytes(self) -> int:
        return 32 * (self.du * self.k + self.dv)

    @property
    def ss_bytes(self) -> int:
        return 32


PARAMS: dict[str, Params] = {
    "ML-KEM-512": Params("ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4),
    "ML-KEM-768": Params("ML-KEM-768", k=3, eta1=2, eta2=2, du=10, dv=4),
    "ML-KEM-1024": Params("ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5),
}


class MLKEMError(ValueError):
    """Error de validacion de entrada (FIPS 203, seccion 7)."""


# ---------------------------------------------------------------------------
# Funciones auxiliares: bits y bytes (FIPS 203, Algoritmos 5 y 6)
# ---------------------------------------------------------------------------
def bitrev7(i: int) -> int:
    """Invierte los 7 bits menos significativos de i."""
    r = 0
    for _ in range(7):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


def byte_encode(coeffs: list[int], d: int) -> bytes:
    """ByteEncode_d: empaqueta 256 coeficientes en d bits c/u, LSB primero."""
    if len(coeffs) != N:
        raise ValueError("ByteEncode requiere 256 coeficientes")
    mask = (1 << d) - 1
    out = bytearray()
    acc = 0
    nbits = 0
    for c in coeffs:
        acc |= (c & mask) << nbits
        nbits += d
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    assert len(out) == 32 * d
    return bytes(out)


def byte_decode(data: bytes, d: int) -> list[int]:
    """ByteDecode_d: des-empaqueta 256 coeficientes de d bits, LSB primero."""
    if len(data) != 32 * d:
        raise ValueError(f"ByteDecode_{d} espera {32 * d} bytes, recibio {len(data)}")
    mask = (1 << d) - 1
    coeffs: list[int] = []
    acc = 0
    nbits = 0
    idx = 0
    for _ in range(N):
        while nbits < d:
            acc |= data[idx] << nbits
            idx += 1
            nbits += 8
        coeffs.append(acc & mask)
        acc >>= d
        nbits -= d
    return coeffs


# ---------------------------------------------------------------------------
# Compresion / descompresion (FIPS 203, seccion 4.2.1)
# ---------------------------------------------------------------------------
def compress(x: int, d: int) -> int:
    """Compress_d(x) = round((2^d / q) * x) mod 2^d."""
    return (((x << d) + Q // 2) // Q) & ((1 << d) - 1)


def decompress(y: int, d: int) -> int:
    """Decompress_d(y) = round((q / 2^d) * y)."""
    return ((y * Q) + (1 << (d - 1))) >> d


# ---------------------------------------------------------------------------
# Muestreo (FIPS 203, Algoritmos 7 y 8)
# ---------------------------------------------------------------------------
def _shake128_stream(seed: bytes, i: int, j: int):
    """Generador XOF(seed, i, j) = SHAKE128(seed || i || j), lectura incremental."""
    xof = hashlib.shake_128(seed + bytes([i, j]))
    # SHAKE de hashlib no expone lectura incremental: se regenera con
    # longitud creciente. El prefijo es identico, por lo que es equivalente.
    buf = b""
    length = 1024
    pos = 0
    while True:
        if pos + 3 > len(buf):
            length *= 2
            buf = xof.digest(length)
        yield buf[pos], buf[pos + 1], buf[pos + 2]
        pos += 3


def sample_ntt(seed: bytes, i: int, j: int) -> list[int]:
    """SampleNTT: muestreo uniforme en R_q por rechazo (Algoritmo 7)."""
    coeffs: list[int] = []
    for b0, b1, b2 in _shake128_stream(seed, i, j):
        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2
        if d1 < Q:
            coeffs.append(d1)
            if len(coeffs) == N:
                break
        if d2 < Q:
            coeffs.append(d2)
            if len(coeffs) == N:
                break
    return coeffs


def _prf(eta: int, s: bytes, b: int) -> bytes:
    """PRF_eta(s, b) = SHAKE256(s || b, 64*eta)."""
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def sample_poly_cbd_from_bytes(B: bytes, eta: int) -> list[int]:
    """SamplePolyCBD_eta a partir de los 64*eta bytes de PRF (Algoritmo 8)."""
    if len(B) != 64 * eta:
        raise ValueError("SamplePolyCBD requiere 64*eta bytes")
    bits = []
    for byte in B:
        for t in range(8):
            bits.append((byte >> t) & 1)
    f = [0] * N
    for i in range(N):
        base = 2 * i * eta
        x = sum(bits[base : base + eta])
        y = sum(bits[base + eta : base + 2 * eta])
        f[i] = (x - y) % Q
    return f


def sample_poly_cbd_prf(sigma: bytes, counter: int, eta: int) -> list[int]:
    """SamplePolyCBD_eta(PRF_eta(sigma, counter))."""
    return sample_poly_cbd_from_bytes(_prf(eta, sigma, counter), eta)


# ---------------------------------------------------------------------------
# NTT (FIPS 203, Algoritmos 9, 10, 11 y 12)
# ---------------------------------------------------------------------------
def ntt(f: list[int]) -> list[int]:
    """NTT en R_q (Algoritmo 9)."""
    f = [x % Q for x in f]
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = pow(ZETA, bitrev7(i), Q)
            i += 1
            for j in range(start, start + length):
                t = (zeta * f[j + length]) % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def inv_ntt(f: list[int]) -> list[int]:
    """NTT^-1 en R_q (Algoritmo 10)."""
    f = [x % Q for x in f]
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = pow(ZETA, bitrev7(i), Q)
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2
    return [(x * INV128) % Q for x in f]


def base_case_multiply(a0: int, a1: int, b0: int, b1: int, zeta: int) -> tuple[int, int]:
    """BaseCaseMultiply (Algoritmo 12)."""
    c0 = (a0 * b0 + a1 * b1 * zeta) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def multiply_ntts(f: list[int], g: list[int]) -> list[int]:
    """MultiplyNTTs: multiplicacion de polinomios en el dominio NTT (Algoritmo 11)."""
    h = [0] * N
    for i in range(128):
        zeta = pow(ZETA, 2 * bitrev7(i) + 1, Q)
        h[2 * i], h[2 * i + 1] = base_case_multiply(
            f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], zeta
        )
    return h


# ---------------------------------------------------------------------------
# Utilidades de polinomios
# ---------------------------------------------------------------------------
def _add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


def _zero() -> list[int]:
    return [0] * N


# ---------------------------------------------------------------------------
# K-PKE (FIPS 203, Algoritmos 13, 14 y 15) -- parte interna de ML-KEM
# ---------------------------------------------------------------------------
def _gen_matrix(rho: bytes, k: int) -> list[list[list[int]]]:
    """Genera la matriz A_hat con A_hat[i][j] = SampleNTT(XOF(rho, j, i)).

    Nota: el estandar genera en KeyGen con (rho, j, i) y en Encrypt con
    (rho, i, j); ambas construcciones son transpuestas entre si y el uso
    posterior en cada algoritmo hace que el producto sea consistente.
    Aqui se usa siempre la convencion de KeyGen y las formulas de Encrypt
    se ajustan en consecuencia (ver K_PKE_encrypt).
    """
    return [[sample_ntt(rho, j, i) for j in range(k)] for i in range(k)]


def k_pke_keygen(params: Params, d: bytes) -> tuple[bytes, bytes]:
    """K-PKE.KeyGen (Algoritmo 13). Devuelve (ek_pke, dk_pke)."""
    k = params.k
    g = hashlib.sha3_512(d + bytes([k])).digest()  # G(d || k)
    rho, sigma = g[:32], g[32:]
    A = _gen_matrix(rho, k)

    s: list[list[int]] = []
    e: list[list[int]] = []
    counter = 0
    for _ in range(k):
        s.append(sample_poly_cbd_prf(sigma, counter, params.eta1))
        counter += 1
    for _ in range(k):
        e.append(sample_poly_cbd_prf(sigma, counter, params.eta1))
        counter += 1

    s_hat = [ntt(x) for x in s]
    e_hat = [ntt(x) for x in e]

    t_hat: list[list[int]] = []
    for i in range(k):
        acc = _zero()
        for j in range(k):
            acc = _add(acc, multiply_ntts(A[i][j], s_hat[j]))
        t_hat.append(_add(acc, e_hat[i]))

    ek = b"".join(byte_encode(p, 12) for p in t_hat) + rho
    dk = b"".join(byte_encode(p, 12) for p in s_hat)
    return ek, dk


def k_pke_encrypt(params: Params, ek: bytes, m: bytes, r: bytes) -> bytes:
    """K-PKE.Encrypt (Algoritmo 14)."""
    k = params.k
    if len(ek) != params.ek_bytes:
        raise MLKEMError("ek con longitud incorrecta")
    if len(m) != 32 or len(r) != 32:
        raise MLKEMError("m y r deben ser de 32 bytes")

    t_hat = [byte_decode(ek[384 * i : 384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k :]
    A = _gen_matrix(rho, k)  # A[i][j] = SampleNTT(XOF(rho, j, i)) = A_hat_kg[i][j]

    y: list[list[int]] = []
    counter = 0
    for _ in range(k):
        y.append(sample_poly_cbd_prf(r, counter, params.eta1))
        counter += 1
    e1: list[list[int]] = []
    for _ in range(k):
        e1.append(sample_poly_cbd_prf(r, counter, params.eta2))
        counter += 1
    e2 = sample_poly_cbd_prf(r, counter, params.eta2)

    y_hat = [ntt(v) for v in y]

    # u = NTT^-1(A_hat^T . y_hat) + e1  (A_hat^T[i][j] = A[j][i])
    u: list[list[int]] = []
    for i in range(k):
        acc = _zero()
        for j in range(k):
            acc = _add(acc, multiply_ntts(A[j][i], y_hat[j]))
        u.append(_add(inv_ntt(acc), e1[i]))

    # v = NTT^-1(t_hat . y_hat) + e2 + Decompress_1(ByteDecode_1(m))
    acc = _zero()
    for i in range(k):
        acc = _add(acc, multiply_ntts(t_hat[i], y_hat[i]))
    mu = [decompress(x, 1) for x in byte_decode(m, 1)]
    v = _add(_add(inv_ntt(acc), e2), mu)

    c1 = b"".join(
        byte_encode([compress(x, params.du) for x in u[i]], params.du) for i in range(k)
    )
    c2 = byte_encode([compress(x, params.dv) for x in v], params.dv)
    return c1 + c2


def k_pke_decrypt(params: Params, dk_pke: bytes, c: bytes) -> bytes:
    """K-PKE.Decrypt (Algoritmo 15)."""
    k = params.k
    if len(dk_pke) != 384 * k:
        raise MLKEMError("dk_pke con longitud incorrecta")
    if len(c) != params.ct_bytes:
        raise MLKEMError("c con longitud incorrecta")

    c1 = c[: 32 * params.du * k]
    c2 = c[32 * params.du * k :]

    s_hat = [byte_decode(dk_pke[384 * i : 384 * (i + 1)], 12) for i in range(k)]

    u = []
    for i in range(k):
        chunk = c1[32 * params.du * i : 32 * params.du * (i + 1)]
        u.append([decompress(x, params.du) for x in byte_decode(chunk, params.du)])
    v = [decompress(x, params.dv) for x in byte_decode(c2, params.dv)]

    acc = _zero()
    for i in range(k):
        acc = _add(acc, multiply_ntts(s_hat[i], ntt(u[i])))
    w = _sub(v, inv_ntt(acc))
    return byte_encode([compress(x, 1) for x in w], 1)


# ---------------------------------------------------------------------------
# Verificacion de llaves (FIPS 203, secciones 7.2 y 7.3)
# ---------------------------------------------------------------------------
def check_ek(params: Params, ek: bytes) -> None:
    """Comprobacion de la llave de encapsulamiento (FIPS 203, seccion 7.2).

    Pasos exactos del estandar:
      1. Type check: len(ek) == 384*k + 32.
      2. Modulus check: todo coeficiente decodificado de ek[0:384k] es < q.
    """
    if len(ek) != params.ek_bytes:
        raise MLKEMError(f"ek debe medir {params.ek_bytes} bytes, recibio {len(ek)}")
    body = ek[: 384 * params.k]
    for i in range(params.k):
        for coeff in byte_decode(body[384 * i : 384 * (i + 1)], 12):
            if coeff >= Q:
                raise MLKEMError("modulus check fallido en ek (coeficiente >= q)")


def check_dk(params: Params, dk: bytes) -> None:
    """Comprobacion de la llave de desencapsulamiento (FIPS 203, seccion 7.3).

    Pasos exactos del estandar para `dk` (el type check del ciphertext se hace
    en `decaps`):
      1. Type check: len(dk) == 768*k + 96.
      2. Hash check: H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64].

    Nota: la seccion 7.3 NO exige un modulus check de dk_PKE. Ese chequeo
    (7.1/7.2) aplica a la llave de encapsulamiento; el `ek` embebido en `dk`
    queda cubierto por el hash check. Anadir un rechazo extra por coeficientes
    de dk_PKE >= q seria mas estricto que el estandar y no forma parte de el.
    """
    if len(dk) != params.dk_bytes:
        raise MLKEMError(f"dk debe medir {params.dk_bytes} bytes, recibio {len(dk)}")
    ek = dk[384 * params.k : 768 * params.k + 32]
    h = dk[768 * params.k + 32 : 768 * params.k + 64]
    if hashlib.sha3_256(ek).digest() != h:
        raise MLKEMError("hash check fallido en dk (H(ek) no coincide)")


# ---------------------------------------------------------------------------
# ML-KEM (FIPS 203, Algoritmos 16, 17 y 18)
# ---------------------------------------------------------------------------
def keygen_internal(params: Params, d: bytes, z: bytes) -> tuple[bytes, bytes]:
    """ML-KEM.KeyGen_internal (Algoritmo 16): deterministico dados d y z."""
    if len(d) != 32 or len(z) != 32:
        raise MLKEMError("d y z deben ser de 32 bytes")
    ek_pke, dk_pke = k_pke_keygen(params, d)
    ek = ek_pke
    dk = dk_pke + ek + hashlib.sha3_256(ek).digest() + z
    return ek, dk


def encaps_internal(params: Params, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """ML-KEM.Encaps_internal (Algoritmo 17): deterministico dado m.

    Nota de capas: la verificacion de `ek` corresponde a ML-KEM.Encaps
    (Algoritmo 20), que la ejecuta antes de llamar a esta funcion.
    """
    if len(m) != 32:
        raise MLKEMError("m debe ser de 32 bytes")
    g = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()  # G(m || H(ek))
    k, r = g[:32], g[32:]
    c = k_pke_encrypt(params, ek, m, r)
    return k, c


def decaps_internal(params: Params, dk: bytes, c: bytes) -> bytes:
    """ML-KEM.Decaps_internal (con rechazo implicito, Algoritmo 18)."""
    if len(dk) != params.dk_bytes:
        raise MLKEMError("dk con longitud incorrecta")
    if len(c) != params.ct_bytes:
        raise MLKEMError("c con longitud incorrecta")

    dk_pke = dk[: 384 * params.k]
    ek = dk[384 * params.k : 768 * params.k + 32]
    h = dk[768 * params.k + 32 : 768 * params.k + 64]
    z = dk[768 * params.k + 64 :]

    m_prime = k_pke_decrypt(params, dk_pke, c)
    g = hashlib.sha3_512(m_prime + h).digest()
    k_prime, r_prime = g[:32], g[32:]

    k_bar = hashlib.shake_256(z + c).digest(32)  # J(z || c)
    c_prime = k_pke_encrypt(params, ek, m_prime, r_prime)
    if c_prime != c:
        return k_bar  # rechazo implicito: no se lanza error
    return k_prime


# ---------------------------------------------------------------------------
# API de conveniencia orientada a objetos
# ---------------------------------------------------------------------------
class MLKEM:
    """API de alto nivel de ML-KEM para un conjunto de parametros."""

    def __init__(self, parameter_set: str = "ML-KEM-768"):
        if parameter_set not in PARAMS:
            raise MLKEMError(
                f"conjunto de parametros desconocido: {parameter_set!r}; "
                f"use uno de {sorted(PARAMS)}"
            )
        self.params = PARAMS[parameter_set]

    # -- KeyGen (Algoritmo 19 del estandar, con RBG del sistema) --
    def keygen(self) -> tuple[bytes, bytes]:
        d = os.urandom(32)
        z = os.urandom(32)
        return keygen_internal(self.params, d, z)

    # -- Encaps (Algoritmo 20) --
    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        check_ek(self.params, ek)  # type check + modulus check (FIPS 203, 7.2)
        m = os.urandom(32)
        return encaps_internal(self.params, ek, m)

    # -- Decaps (Algoritmo 21) --
    def decaps(self, dk: bytes, c: bytes) -> bytes:
        return decaps_internal(self.params, dk, c)

    # -- Utilidades de validacion --
    def check_ek(self, ek: bytes) -> None:
        check_ek(self.params, ek)

    def check_dk(self, dk: bytes) -> None:
        check_dk(self.params, dk)

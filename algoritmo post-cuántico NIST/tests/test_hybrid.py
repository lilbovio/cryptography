"""
Pruebas de la capa hibrida KEM-DEM (ML-KEM + AES-256-GCM).

Cubre los criterios de aceptacion AC-07, AC-08, AC-09 y AC-14.

Ejecutar:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hybrid import (  # noqa: E402
    HEADER_BYTES,
    MAGIC,
    NONCE_BYTES,
    TAG_BYTES,
    VERSION,
    HybridCipher,
    IntegrityError,
    PacketError,
    derive_key,
)


class TestHybridRoundtrip(unittest.TestCase):
    """AC-07: el mensaje se recupera exactamente para los 3 conjuntos."""

    MESSAGES = [b"", b"A", b"x" * 15, b"x" * 16, b"y" * 1000]

    def test_roundtrip_all_sets(self) -> None:
        for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
            suite = HybridCipher(name)
            for msg in self.MESSAGES:
                with self.subTest(param=name, size=len(msg)):
                    ek, dk = suite.keygen()
                    packet = suite.encrypt(ek, msg)
                    self.assertEqual(suite.decrypt(dk, packet), msg)

    def test_utf8_and_large_message(self) -> None:
        suite = HybridCipher("ML-KEM-768")
        ek, dk = suite.keygen()
        msg = ("Criptografia post-cuantica \u00f1\u00e1\u00e9 " * 500).encode("utf-8")
        self.assertEqual(suite.decrypt(dk, suite.encrypt(ek, msg)), msg)

    def test_secret_agreement(self) -> None:
        """El KEM produce el mismo secreto en emisor y receptor."""
        suite = HybridCipher("ML-KEM-768")
        ek, dk = suite.keygen()
        k1, c = suite.encapsulate(ek)
        k2 = suite.decapsulate(dk, c)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_hkdf_is_deterministic_and_binds_ciphertext(self) -> None:
        """Dos c_kem distintos producen llaves AES distintas con el mismo K."""
        k = bytes(32)
        a = derive_key(k, b"\x00" * 1088, "ML-KEM-768")
        b = derive_key(k, b"\x01" * 1088, "ML-KEM-768")
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, b)
        self.assertEqual(a, derive_key(k, b"\x00" * 1088, "ML-KEM-768"))


class TestPacketFormat(unittest.TestCase):
    """AC-14: el formato del paquete es explicito y verificable."""

    def test_header_fields(self) -> None:
        suite = HybridCipher("ML-KEM-1024")
        ek, dk = suite.keygen()
        packet = suite.encrypt(ek, b"hola")
        self.assertEqual(packet[:4], MAGIC)
        self.assertEqual(packet[4], VERSION)
        self.assertEqual(packet[5], 3)  # ML-KEM-1024
        (ct_len,) = struct.unpack(">H", packet[6:8])
        self.assertEqual(ct_len, suite.kem.params.ct_bytes)
        total = HEADER_BYTES + ct_len + NONCE_BYTES + len(b"hola") + TAG_BYTES
        self.assertEqual(len(packet), total)

    def test_packet_has_no_plaintext(self) -> None:
        suite = HybridCipher("ML-KEM-768")
        ek, dk = suite.keygen()
        msg = b"MARCADOR_UNICO_DE_TEXTO_PLANO_1234567890"
        self.assertNotIn(msg, suite.encrypt(ek, msg))

    def test_two_encryptions_differ_by_nonce(self) -> None:
        suite = HybridCipher("ML-KEM-768")
        ek, dk = suite.keygen()
        p1 = suite.encrypt(ek, b"igual")
        p2 = suite.encrypt(ek, b"igual")
        self.assertNotEqual(p1, p2)


class TestDemAuthentication(unittest.TestCase):
    """AC-08: cualquier manipulacion del paquete es detectada."""

    def setUp(self) -> None:
        self.suite = HybridCipher("ML-KEM-768")
        self.ek, self.dk = self.suite.keygen()
        self.packet = self.suite.encrypt(self.ek, b"mensaje autenticado")

    def _flip(self, position: int) -> bytes:
        bad = bytearray(self.packet)
        bad[position] ^= 0x01
        return bytes(bad)

    def test_every_byte_is_authenticated(self) -> None:
        """Cambiar un bit en cualquier posicion debe fallar (o rechazarse)."""
        for pos in range(len(self.packet)):
            with self.subTest(offset=pos):
                with self.assertRaises((IntegrityError, PacketError)):
                    self.suite.decrypt(self.dk, self._flip(pos))

    def test_tag_tamper(self) -> None:
        with self.assertRaises(IntegrityError):
            self.suite.decrypt(self.dk, self._flip(len(self.packet) - 1))

    def test_nonce_tamper(self) -> None:
        ct_len = self.suite.kem.params.ct_bytes
        with self.assertRaises(IntegrityError):
            self.suite.decrypt(self.dk, self._flip(HEADER_BYTES + ct_len + 3))

    def test_kem_ciphertext_tamper(self) -> None:
        with self.assertRaises(IntegrityError):
            self.suite.decrypt(self.dk, self._flip(HEADER_BYTES + 10))

    def test_wrong_aad(self) -> None:
        ek, dk = self.suite.keygen()
        packet = self.suite.encrypt(ek, b"dato", aad=b"contexto-A")
        self.assertEqual(self.suite.decrypt(dk, packet, aad=b"contexto-A"), b"dato")
        with self.assertRaises(IntegrityError):
            self.suite.decrypt(dk, packet, aad=b"contexto-B")


class TestWrongKeys(unittest.TestCase):
    """AC-09: con la llave privada equivocada no se obtiene el mensaje."""

    def test_wrong_decapsulation_key(self) -> None:
        suite = HybridCipher("ML-KEM-768")
        ek1, dk1 = suite.keygen()
        ek2, dk2 = suite.keygen()
        packet = suite.encrypt(ek1, b"secreto")
        with self.assertRaises(IntegrityError):
            suite.decrypt(dk2, packet)

    def test_wrong_parameter_set_rejected(self) -> None:
        a = HybridCipher("ML-KEM-768")
        b = HybridCipher("ML-KEM-512")
        ek, dk = a.keygen()
        packet = a.encrypt(ek, b"dato")
        with self.assertRaises(PacketError):
            b.decrypt(dk, packet)


class TestMalformedPackets(unittest.TestCase):
    """AC-14: entradas malformadas se rechazan con PacketError."""

    def setUp(self) -> None:
        self.suite = HybridCipher("ML-KEM-768")
        self.ek, self.dk = self.suite.keygen()
        self.packet = self.suite.encrypt(self.ek, b"dato")

    def test_empty(self) -> None:
        with self.assertRaises(PacketError):
            self.suite.decrypt(self.dk, b"")

    def test_truncated(self) -> None:
        with self.assertRaises(PacketError):
            self.suite.decrypt(self.dk, self.packet[:20])

    def test_bad_magic(self) -> None:
        bad = b"XXXX" + self.packet[4:]
        with self.assertRaises(PacketError):
            self.suite.decrypt(self.dk, bad)

    def test_bad_version(self) -> None:
        bad = self.packet[:4] + b"\x02" + self.packet[5:]
        with self.assertRaises(PacketError):
            self.suite.decrypt(self.dk, bad)

    def test_bad_ct_length_field(self) -> None:
        bad = bytearray(self.packet)
        bad[6:8] = struct.pack(">H", 9999)
        with self.assertRaises(PacketError):
            self.suite.decrypt(self.dk, bytes(bad))

    def test_non_bytes_input(self) -> None:
        with self.assertRaises(PacketError):
            self.suite.decrypt(self.dk, "no soy bytes")  # type: ignore[arg-type]

    def test_unknown_parameter_set(self) -> None:
        with self.assertRaises(Exception):
            HybridCipher("ML-KEM-999")


if __name__ == "__main__":
    unittest.main(verbosity=2)

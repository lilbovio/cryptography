"""
Pruebas de FALLA (criterios de falla documentados, F-01 ... F-10).

Estas pruebas verifican que el sistema falla de forma segura ("fail closed"):
ante una manipulacion, llave incorrecta o entrada invalida, NO debe devolver
texto plano ni un secreto util, y debe lanzar el error esperado.

Que una prueba de este archivo pase significa que la falla esperada ocurrio.
Si alguna falla, el criterio de aceptacion correspondiente NO se cumple.

Ejecutar:
    python -m unittest tests.test_failures -v      (desde la raiz)
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import ml_kem as M  # noqa: E402
from hybrid import HybridCipher, IntegrityError, PacketError  # noqa: E402


class FallasDelKEM(unittest.TestCase):
    """Fallas del KEM (FIPS 203)."""

    def test_F01_ciphertext_alterado_no_revela_el_secreto(self) -> None:
        """F-01: c alterado -> rechazo implicito (K_bar), nunca el K original."""
        kem = M.MLKEM("ML-KEM-768")
        ek, dk = kem.keygen()
        k, c = kem.encaps(ek)
        for pos in (0, len(c) // 3, len(c) // 2, len(c) - 1):
            with self.subTest(pos=pos):
                bad = bytearray(c)
                bad[pos] ^= 0x80
                bad = bytes(bad)
                k_bad = kem.decaps(dk, bad)  # no debe lanzar excepcion
                self.assertNotEqual(k_bad, k)
                z = dk[768 * kem.params.k + 64 :]
                self.assertEqual(k_bad, hashlib.shake_256(z + bad).digest(32))

    def test_F04_ek_no_canonica_es_rechazada(self) -> None:
        """F-04: ek con coeficiente >= q -> MLKEMError (modulus check)."""
        kem = M.MLKEM("ML-KEM-768")
        ek, _ = kem.keygen()
        bad = bytearray(ek)
        bad[0] = 0x01
        bad[1] = (bad[1] & 0xF0) | 0x0D  # 0xD01 = 3329 = q
        with self.assertRaises(M.MLKEMError):
            kem.check_ek(bytes(bad))
        with self.assertRaises(M.MLKEMError):
            kem.encaps(bytes(bad))

    def test_F05_dk_con_hash_inconsistente_es_rechazada(self) -> None:
        """F-05: dk cuyo H(ek) no coincide -> MLKEMError (hash check)."""
        kem = M.MLKEM("ML-KEM-768")
        _, dk = kem.keygen()
        bad = bytearray(dk)
        bad[768 * kem.params.k + 40] ^= 0xFF
        with self.assertRaises(M.MLKEMError):
            kem.check_dk(bytes(bad))

    def test_F06_longitudes_incorrectas(self) -> None:
        """F-06: longitudes invalidas -> MLKEMError explicito."""
        kem = M.MLKEM("ML-KEM-768")
        ek, dk = kem.keygen()
        with self.assertRaises(M.MLKEMError):
            kem.encaps(ek[:-1])
        with self.assertRaises(M.MLKEMError):
            kem.decaps(dk, b"\x00" * 10)
        with self.assertRaises(M.MLKEMError):
            kem.check_dk(dk[:-1])

    def test_F09_decaps_con_ciphertext_de_longitud_incorrecta(self) -> None:
        """F-09: c con longitud distinta a la oficial -> error, no basura."""
        for name in M.PARAMS:
            with self.subTest(param=name):
                kem = M.MLKEM(name)
                _, dk = kem.keygen()
                for n in (0, 1, kem.params.ct_bytes - 1, kem.params.ct_bytes + 1):
                    with self.assertRaises(M.MLKEMError):
                        kem.decaps(dk, b"\x00" * n)


class FallasDelEsquemaHibrido(unittest.TestCase):
    """Fallas del KEM-DEM (F-02, F-03, F-07, F-08, F-10)."""

    def setUp(self) -> None:
        self.suite = HybridCipher("ML-KEM-768")
        self.ek, self.dk = self.suite.keygen()
        self.msg = b"contenido confidencial"
        self.packet = self.suite.encrypt(self.ek, self.msg)

    def test_F02_paquete_alterado_es_rechazado(self) -> None:
        """F-02: cualquier bit alterado -> IntegrityError/PacketError, sin dato."""
        for pos in (0, 8, 100, len(self.packet) // 2, len(self.packet) - 1):
            with self.subTest(pos=pos):
                bad = bytearray(self.packet)
                bad[pos] ^= 0x01
                with self.assertRaises((IntegrityError, PacketError)):
                    self.suite.decrypt(self.dk, bytes(bad))

    def test_F03_llave_privada_incorrecta_no_descifra(self) -> None:
        """F-03: dk de otra sesion -> IntegrityError, no texto plano."""
        _, otro_dk = self.suite.keygen()
        with self.assertRaises(IntegrityError):
            self.suite.decrypt(otro_dk, self.packet)

    def test_F07_parametro_del_paquete_no_se_degrada(self) -> None:
        """F-07: paquete de otro conjunto -> PacketError (sin downgrade)."""
        suite512 = HybridCipher("ML-KEM-512")
        ek512, dk512 = suite512.keygen()
        packet512 = suite512.encrypt(ek512, b"dato")
        with self.assertRaises(PacketError):
            self.suite.decrypt(dk512, packet512)
        with self.assertRaises(PacketError):
            suite512.decrypt(self.dk, self.packet)

    def test_F08_tamano_de_mensaje_invalido(self) -> None:
        """F-08: plaintext no-bytes -> error explicito (control de tipos)."""
        with self.assertRaises(Exception):
            self.suite.encrypt(self.ek, "texto, no bytes")  # type: ignore[arg-type]

    def test_F10_paquete_truncado_o_sin_tag(self) -> None:
        """F-10: quitar bytes (incluido el tag) -> rechazo, nunca texto plano.

        Un recorte que deja el paquete por debajo del minimo produce
        PacketError; un recorte del ciphertext/tag produce IntegrityError
        (el tag GCM ya no valida). Ambos son rechazos seguros.
        """
        for cut in (1, 16, 17, len(self.packet) // 2):
            with self.subTest(cut=cut):
                with self.assertRaises((PacketError, IntegrityError)):
                    self.suite.decrypt(self.dk, self.packet[:-cut])

    def test_F11_paquete_con_magic_incorrecto(self) -> None:
        """F-11: magic distinto -> PacketError (no se interpreta como valido)."""
        bad = b"FAIL" + self.packet[4:]
        with self.assertRaises(PacketError):
            self.suite.decrypt(self.dk, bad)


class ControlPositivo(unittest.TestCase):
    """Control: sin manipulacion, todo funciona (evita falsos positivos)."""

    def test_flujo_correcto(self) -> None:
        suite = HybridCipher("ML-KEM-768")
        ek, dk = suite.keygen()
        msg = b"control positivo"
        self.assertEqual(suite.decrypt(dk, suite.encrypt(ek, msg)), msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)

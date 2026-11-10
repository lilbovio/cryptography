"""
Pruebas de conformidad y correccion de ML-KEM (FIPS 203).

Incluye:
  - KAT (Known Answer Tests) oficiales del NIST (ACVP).
  - Verificacion de tamanos de FIPS 203, Tabla 3.
  - Roundtrip de encapsulamiento/desencapsulamiento.
  - Rechazo implicito (implicit rejection) ante ciphertext alterado.
  - Determinismo de las funciones internas.
  - Verificacion de llaves (FIPS 203, secciones 7.2 y 7.3).
  - Pruebas unitarias de ByteEncode/ByteDecode, NTT y multiplicacion.
  - Interoperabilidad con PQClean (pqcrypto), si esta instalado.

Ejecutar:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import ml_kem as M  # noqa: E402

VECTORS = ROOT / "tests" / "vectors" / "ml_kem_kat.json"


def load_vectors() -> dict:
    if not VECTORS.exists():
        raise unittest.SkipTest(
            "faltan los vectores ACVP; ejecute tools/fetch_acvp_vectors.py"
        )
    return json.loads(VECTORS.read_text(encoding="utf-8"))


class TestKnownAnswerVectors(unittest.TestCase):
    """AC-02, AC-03, AC-04: conformidad exacta con los vectores del NIST."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.v = load_vectors()

    def test_keygen_kat(self) -> None:
        cases = self.v["keygen"]
        self.assertGreaterEqual(len(cases), 6)
        for case in cases:
            with self.subTest(param=case["parameterSet"], tc=case["tcId"]):
                p = M.PARAMS[case["parameterSet"]]
                ek, dk = M.keygen_internal(
                    p, bytes.fromhex(case["d"]), bytes.fromhex(case["z"])
                )
                self.assertEqual(ek.hex().upper(), case["ek"])
                self.assertEqual(dk.hex().upper(), case["dk"])

    def test_encaps_kat(self) -> None:
        cases = self.v["encaps"]
        self.assertGreaterEqual(len(cases), 6)
        for case in cases:
            with self.subTest(param=case["parameterSet"], tc=case["tcId"]):
                p = M.PARAMS[case["parameterSet"]]
                k, c = M.encaps_internal(
                    p, bytes.fromhex(case["ek"]), bytes.fromhex(case["m"])
                )
                self.assertEqual(k.hex().upper(), case["k"])
                self.assertEqual(c.hex().upper(), case["c"])

    def test_decaps_kat(self) -> None:
        cases = self.v["decaps"]
        self.assertGreaterEqual(len(cases), 6)
        for case in cases:
            with self.subTest(param=case["parameterSet"], tc=case["tcId"]):
                p = M.PARAMS[case["parameterSet"]]
                k = M.decaps_internal(
                    p, bytes.fromhex(case["dk"]), bytes.fromhex(case["c"])
                )
                self.assertEqual(k.hex().upper(), case["k"])

    def test_kat_source_is_nist_acvp(self) -> None:
        """Trazabilidad: los vectores deben declarar su origen y hash."""
        self.assertIn("ACVP", self.v["description"])
        self.assertEqual(len(self.v["source_files"]), 4)
        for meta in self.v["source_files"].values():
            self.assertIn("usnistgov/ACVP-Server", meta["url"])
            self.assertEqual(len(meta["sha256"]), 64)


class TestParameterSizes(unittest.TestCase):
    """AC-01: tamanos exactos de FIPS 203, Tabla 3."""

    EXPECTED = {
        "ML-KEM-512": (800, 1632, 768),
        "ML-KEM-768": (1184, 2400, 1088),
        "ML-KEM-1024": (1568, 3168, 1568),
    }

    def test_sizes(self) -> None:
        for name, (ek_b, dk_b, ct_b) in self.EXPECTED.items():
            with self.subTest(param=name):
                p = M.PARAMS[name]
                self.assertEqual(p.ek_bytes, ek_b)
                self.assertEqual(p.dk_bytes, dk_b)
                self.assertEqual(p.ct_bytes, ct_b)
                ek, dk = M.MLKEM(name).keygen()
                self.assertEqual(len(ek), ek_b)
                self.assertEqual(len(dk), dk_b)
                k, c = M.MLKEM(name).encaps(ek)
                self.assertEqual(len(k), 32)
                self.assertEqual(len(c), ct_b)


class TestRoundtrip(unittest.TestCase):
    """AC-05: K == K' para los tres conjuntos y varias semillas."""

    def test_roundtrip_all_sets(self) -> None:
        for name in M.PARAMS:
            kem = M.MLKEM(name)
            for i in range(5):
                with self.subTest(param=name, iter=i):
                    ek, dk = kem.keygen()
                    k1, c = kem.encaps(ek)
                    k2 = kem.decaps(dk, c)
                    self.assertEqual(k1, k2)
                    self.assertEqual(len(k1), 32)

    def test_different_sessions_differ(self) -> None:
        kem = M.MLKEM("ML-KEM-768")
        ek, dk = kem.keygen()
        k1, c1 = kem.encaps(ek)
        k2, c2 = kem.encaps(ek)
        self.assertNotEqual(k1, k2)
        self.assertNotEqual(c1, c2)


class TestDeterminism(unittest.TestCase):
    """AC-10: las funciones internas son deterministas."""

    def test_keygen_deterministic(self) -> None:
        p = M.PARAMS["ML-KEM-768"]
        d, z = bytes(range(32)), bytes(range(32, 64))
        self.assertEqual(M.keygen_internal(p, d, z), M.keygen_internal(p, d, z))

    def test_encaps_deterministic(self) -> None:
        p = M.PARAMS["ML-KEM-768"]
        ek, _ = M.keygen_internal(p, bytes(range(32)), bytes(range(32, 64)))
        m = bytes(range(64, 96))
        self.assertEqual(
            M.encaps_internal(p, ek, m), M.encaps_internal(p, ek, m)
        )


class TestImplicitRejection(unittest.TestCase):
    """AC-06: un ciphertext alterado no produce error, produce K_bar = J(z||c)."""

    def test_tampered_ciphertext_yields_rejection_key(self) -> None:
        for name in M.PARAMS:
            with self.subTest(param=name):
                kem = M.MLKEM(name)
                ek, dk = kem.keygen()
                k, c = kem.encaps(ek)
                bad = bytearray(c)
                bad[0] ^= 0x01
                bad = bytes(bad)
                k_rejected = kem.decaps(dk, bad)  # no lanza excepcion
                self.assertNotEqual(k_rejected, k)
                p = kem.params
                z = dk[768 * p.k + 64 :]
                expected = hashlib.shake_256(z + bad).digest(32)
                self.assertEqual(k_rejected, expected)

    def test_rejection_key_is_stable(self) -> None:
        kem = M.MLKEM("ML-KEM-768")
        ek, dk = kem.keygen()
        _, c = kem.encaps(ek)
        bad = bytes([c[0] ^ 0xFF]) + c[1:]
        self.assertEqual(kem.decaps(dk, bad), kem.decaps(dk, bad))


class TestKeyValidation(unittest.TestCase):
    """AC-11: validacion de llaves de FIPS 203, secciones 7.2 y 7.3."""

    def setUp(self) -> None:
        self.kem = M.MLKEM("ML-KEM-768")
        self.ek, self.dk = self.kem.keygen()

    def test_valid_keys_pass(self) -> None:
        self.kem.check_ek(self.ek)
        self.kem.check_dk(self.dk)

    def test_ek_wrong_length(self) -> None:
        with self.assertRaises(M.MLKEMError):
            self.kem.check_ek(self.ek[:-1])

    def test_dk_wrong_length(self) -> None:
        with self.assertRaises(M.MLKEMError):
            self.kem.check_dk(self.dk[:-1])

    def test_ek_non_canonical_coefficient(self) -> None:
        bad = bytearray(self.ek)
        bad[0] = 0x01
        bad[1] = (bad[1] & 0xF0) | 0x0D  # primer coeficiente 12-bit = 3329 = q
        with self.assertRaises(M.MLKEMError):
            self.kem.check_ek(bytes(bad))

    def test_dk_hash_mismatch(self) -> None:
        p = self.kem.params
        bad = bytearray(self.dk)
        bad[768 * p.k + 32] ^= 0x01  # corrompe H(ek) almacenado
        with self.assertRaises(M.MLKEMError):
            self.kem.check_dk(bytes(bad))

    def test_encaps_rejects_invalid_ek(self) -> None:
        bad = bytearray(self.ek)
        bad[0] = 0x01
        bad[1] = (bad[1] & 0xF0) | 0x0D
        with self.assertRaises(M.MLKEMError):
            self.kem.encaps(bytes(bad))


class TestPrimitives(unittest.TestCase):
    """AC-12: primitivas internas verificadas de forma independiente."""

    def test_byte_encode_decode_roundtrip(self) -> None:
        for d in range(1, 13):
            with self.subTest(d=d):
                vals = [(i * 7919 + 13) % (1 << d) for i in range(256)]
                self.assertEqual(M.byte_decode(M.byte_encode(vals, d), d), vals)
                self.assertEqual(len(M.byte_encode(vals, d)), 32 * d)

    def test_ntt_inverse(self) -> None:
        import random

        rng = random.Random(2024)
        f = [rng.randrange(M.Q) for _ in range(256)]
        self.assertEqual(M.inv_ntt(M.ntt(f)), f)

    def test_ntt_multiplication_matches_schoolbook(self) -> None:
        import random

        rng = random.Random(7)

        def schoolbook(a, b):
            res = [0] * 256
            for i, ai in enumerate(a):
                for j, bj in enumerate(b):
                    k = i + j
                    if k < 256:
                        res[k] += ai * bj
                    else:
                        res[k - 256] -= ai * bj
            return [x % M.Q for x in res]

        a = [rng.randrange(M.Q) for _ in range(256)]
        b = [rng.randrange(M.Q) for _ in range(256)]
        via_ntt = M.inv_ntt(M.multiply_ntts(M.ntt(a), M.ntt(b)))
        self.assertEqual(via_ntt, schoolbook(a, b))

    def test_compress_bounds(self) -> None:
        for d in (1, 4, 10, 11, 12):
            with self.subTest(d=d):
                for x in range(0, M.Q, 97):
                    c = M.compress(x, d)
                    self.assertTrue(0 <= c < (1 << d))
                    y = M.decompress(c, d)
                    self.assertTrue(0 <= y < M.Q)

    def test_sample_ntt_and_prf(self) -> None:
        """SampleNTT es determinista, uniforme en rango y el PRF depende del contador."""
        seed = bytes(range(32))
        p1 = M.sample_ntt(seed, 1, 2)
        p2 = M.sample_ntt(seed, 1, 2)
        self.assertEqual(p1, p2)
        self.assertEqual(len(p1), 256)
        self.assertTrue(all(0 <= x < M.Q for x in p1))
        self.assertNotEqual(p1, M.sample_ntt(seed, 2, 1))
        b0 = M._prf(2, seed, 0)
        self.assertEqual(len(b0), 64 * 2)
        self.assertNotEqual(b0, M._prf(2, seed, 1))


class TestInteropPQClean(unittest.TestCase):
    """AC-13: interoperabilidad con una implementacion independiente (PQClean)."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"pqcrypto no disponible: {exc}")
        cls.refs = {
            "ML-KEM-512": ml_kem_512,
            "ML-KEM-768": ml_kem_768,
            "ML-KEM-1024": ml_kem_1024,
        }

    def test_interop_both_directions(self) -> None:
        for name, ref in self.refs.items():
            with self.subTest(param=name):
                kem = M.MLKEM(name)
                pk, sk = ref.keygen()
                c, ss = ref.encaps(pk)
                self.assertEqual(kem.decaps(bytes(sk), bytes(c)), ss)

                k, c2 = kem.encaps(bytes(pk))
                self.assertEqual(ref.decaps(sk, c2), k)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""
Benchmark de ML-KEM (FIPS 203) y de la capa hibrida.

Uso:
    python tools/benchmark.py [--iter N]

Mide mediana y media en milisegundos. Los numeros son de esta implementacion
en Python puro (sin optimizar), por lo que sirven para comparar ordenes de
magnitud, no para comparar con implementaciones en C.
"""

from __future__ import annotations

import argparse
import pathlib
import statistics
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hybrid import HybridCipher  # noqa: E402


def timeit(fn, n: int) -> tuple[float, float]:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.median(samples), statistics.mean(samples)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iter", type=int, default=15)
    args = ap.parse_args()
    n = args.iter

    print(f"iteraciones por operacion: {n}")
    print()
    header = f"{'conjunto':<12} {'keygen':>9} {'encaps':>9} {'decaps':>9} {'encrypt':>9} {'decrypt':>9}"
    print(header)
    print("-" * len(header))

    for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        suite = HybridCipher(name)
        ek, dk = suite.keygen()
        msg = b"x" * 32
        packet = suite.encrypt(ek, msg)

        t_keygen, _ = timeit(suite.keygen, n)
        t_encaps, _ = timeit(lambda: suite.encapsulate(ek), n)
        k, c = suite.encapsulate(ek)
        t_decaps, _ = timeit(lambda: suite.decapsulate(dk, c), n)
        t_enc, _ = timeit(lambda: suite.encrypt(ek, msg), max(3, n // 2))
        t_dec, _ = timeit(lambda: suite.decrypt(dk, packet), max(3, n // 2))

        print(
            f"{name:<12} {t_keygen:8.2f}ms {t_encaps:8.2f}ms {t_decaps:8.2f}ms "
            f"{t_enc:8.2f}ms {t_dec:8.2f}ms"
        )

    print()
    suite = HybridCipher("ML-KEM-768")
    ek, dk = suite.keygen()
    for size in (32, 1024, 1024 * 1024):
        msg = b"z" * size
        packet = suite.encrypt(ek, msg)
        t_enc, _ = timeit(lambda: suite.encrypt(ek, msg), 5)
        t_dec, _ = timeit(lambda: suite.decrypt(dk, packet), 5)
        print(
            f"ML-KEM-768, mensaje {size:>8} B: encrypt={t_enc:7.2f} ms, "
            f"decrypt={t_dec:7.2f} ms, paquete={len(packet)} B"
        )


if __name__ == "__main__":
    main()

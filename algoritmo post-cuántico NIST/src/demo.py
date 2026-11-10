"""
Demostracion completa del algoritmo post-cuantico ML-KEM (FIPS 203) con
cifrado hibrido de un mensaje real mediante ML-KEM + AES-256-GCM.

Flujo (lo que pide la actividad):
    1. Generar llave publica/privada (ML-KEM.KeyGen).
    2. Generar un secreto compartido y su ciphertext (ML-KEM.Encaps).
    3. Cifrar el mensaje con el secreto (AES-256-GCM, KEM-DEM).
    4. Descifrar el mensaje (ML-KEM.Decaps + AES-256-GCM).
    5. Verificar que el mensaje recuperado es identico al original.
    6. Demostrar que un paquete alterado es rechazado (autenticacion).

Uso:
    python src/demo.py
    python src/demo.py --param ML-KEM-1024 --mensaje "texto de prueba"
    python src/demo.py --guardar
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from hybrid import HybridCipher, IntegrityError  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


def hexdump_short(data: bytes, n: int = 16) -> str:
    h = data[:n].hex().upper()
    return h + ("..." if len(data) > n else "")


def rule(title: str) -> None:
    print()
    print("=" * 74)
    print(title)
    print("=" * 74)


def main() -> int:
    ap = argparse.ArgumentParser(description="Demo ML-KEM (FIPS 203) + AES-256-GCM")
    ap.add_argument("--param", default="ML-KEM-768",
                    choices=["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    ap.add_argument("--mensaje", default="Mensaje secreto de la clase de criptografia.")
    ap.add_argument("--guardar", action="store_true",
                    help="guarda llaves, ciphertext y paquete en salida/")
    args = ap.parse_args()

    mensaje = args.mensaje.encode("utf-8")
    suite = HybridCipher(args.param)
    p = suite.kem.params

    rule(f"0. PARAMETROS  ({args.param}, FIPS 203 Tablas 2 y 3)")
    print(f"  k={p.k}  eta1={p.eta1}  eta2={p.eta2}  du={p.du}  dv={p.dv}")
    print(f"  |ek| = {p.ek_bytes} B   |dk| = {p.dk_bytes} B   |c_kem| = {p.ct_bytes} B")

    rule("1. GENERACION DE LLAVES  (ML-KEM.KeyGen)")
    t0 = time.perf_counter()
    ek, dk = suite.keygen()
    t_keygen = time.perf_counter() - t0
    suite.check_ek(ek)
    suite.check_dk(dk)
    print(f"  llave publica  ek ({len(ek)} B): {hexdump_short(ek, 24)}")
    print(f"  llave privada  dk ({len(dk)} B): (no se imprime completa)")
    print(f"  validacion FIPS 203 7.2/7.3: OK")
    print(f"  tiempo: {t_keygen * 1000:.2f} ms")

    rule("2. ENCAPSULAMIENTO  (ML-KEM.Encaps -> llave + secreto)")
    t0 = time.perf_counter()
    secreto_emisor, c_kem = suite.encapsulate(ek)
    t_encaps = time.perf_counter() - t0
    print(f"  secreto K (32 B): {secreto_emisor.hex().upper()}")
    print(f"  ciphertext KEM ({len(c_kem)} B): {hexdump_short(c_kem, 24)}")
    print(f"  tiempo: {t_encaps * 1000:.2f} ms")

    rule("3. CIFRADO DEL MENSAJE  (KEM-DEM: HKDF-SHA256 + AES-256-GCM)")
    t0 = time.perf_counter()
    paquete = suite.encrypt(ek, mensaje)
    t_encrypt = time.perf_counter() - t0
    print(f"  mensaje original ({len(mensaje)} B): {mensaje!r}")
    print(f"  paquete ({len(paquete)} B): {hexdump_short(paquete, 24)}")
    print(f"  tiempo: {t_encrypt * 1000:.2f} ms")

    rule("4. DESENCAPSULAMIENTO  (ML-KEM.Decaps -> mismo secreto)")
    t0 = time.perf_counter()
    secreto_receptor = suite.decapsulate(dk, c_kem)
    t_decaps = time.perf_counter() - t0
    print(f"  secreto K' (32 B): {secreto_receptor.hex().upper()}")
    print(f"  K == K' : {secreto_emisor == secreto_receptor}")
    print(f"  tiempo: {t_decaps * 1000:.2f} ms")

    rule("5. DESCIFRADO DEL MENSAJE")
    t0 = time.perf_counter()
    recuperado = suite.decrypt(dk, paquete)
    t_decrypt = time.perf_counter() - t0
    print(f"  mensaje recuperado ({len(recuperado)} B): {recuperado!r}")
    print(f"  tiempo: {t_decrypt * 1000:.2f} ms")
    print()
    print(f"  RESULTADO: {'OK - mensaje identico' if recuperado == mensaje else 'FALLO'}")

    rule("6. PRUEBA NEGATIVA: paquete alterado debe ser rechazado")
    alterado = bytearray(paquete)
    alterado[-1] ^= 0x01  # cambia 1 bit del tag/ciphertext
    try:
        suite.decrypt(dk, bytes(alterado))
        print("  ERROR: el paquete alterado fue aceptado (no deberia ocurrir)")
        return 1
    except IntegrityError as exc:
        print(f"  RECHAZADO correctamente: {exc}")

    if args.guardar:
        out = ROOT / "salida"
        out.mkdir(exist_ok=True)
        (out / "llave_publica_ek.bin").write_bytes(ek)
        (out / "llave_privada_dk.bin").write_bytes(dk)
        (out / "ciphertext_kem.bin").write_bytes(c_kem)
        (out / "paquete.bin").write_bytes(paquete)
        (out / "mensaje_original.txt").write_bytes(mensaje)
        print()
        print(f"  archivos guardados en: {out}")

    print()
    print(f"Tiempos totales: keygen={t_keygen*1000:.2f} ms, encaps={t_encaps*1000:.2f} ms, "
          f"encrypt={t_encrypt*1000:.2f} ms, decaps={t_decaps*1000:.2f} ms, "
          f"decrypt={t_decrypt*1000:.2f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

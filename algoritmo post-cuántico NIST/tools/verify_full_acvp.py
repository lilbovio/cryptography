"""
Verificacion extendida contra el conjunto COMPLETO de vectores oficiales ACVP
del NIST para ML-KEM (FIPS 203).

A diferencia de la suite de pruebas (que usa un subconjunto de 2 casos por grupo
para mantenerla rapida), este script valida TODOS los casos descargados:

    keyGen                 3 grupos x 25 = 75
    encapsulation          3 grupos x 25 = 75
    decapsulation          3 grupos x 10 = 30
    decapsulationKeyCheck  3 grupos x 10 = 30
    encapsulationKeyCheck  3 grupos x 10 = 30
    -------------------------------------------------
    total                                240

Los grupos de *KeyCheck* son los que valida ACVP para las comprobaciones de
entrada de FIPS 203, secciones 7.2 (ek) y 7.3 (dk). Se usan `check_ek` y
`check_dk`, que implementan exactamente los pasos del estandar:
    - ek: type check + modulus check (todo coeficiente < q).
    - dk: type check + hash check (H(ek) almacenado coincide).

Fuente de los vectores (cache local, descargada por fetch_acvp_vectors.py):
    tests/vectors/_acvp_cache/{keygen,encap}_{prompt,expected}.json

Uso:
    python tools/verify_full_acvp.py [--verbose]

Codigo de salida: 0 si TODO coincide, 1 en caso contrario.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import ml_kem as M  # noqa: E402

CACHE = ROOT / "tests" / "vectors" / "_acvp_cache"
FILES = {
    "keygen_prompt": CACHE / "keygen_prompt.json",
    "keygen_expected": CACHE / "keygen_expected.json",
    "encap_prompt": CACHE / "encap_prompt.json",
    "encap_expected": CACHE / "encap_expected.json",
}

# Resultado por categoria: [correctos, total]
Stats = dict[str, list[int]]


def load() -> dict[str, dict]:
    missing = [str(p) for p in FILES.values() if not p.exists()]
    if missing:
        sys.exit(
            "ERROR: faltan archivos de vectores ACVP:\n  "
            + "\n  ".join(missing)
            + "\n\nEjecute primero: python tools/fetch_acvp_vectors.py --per-group 25"
        )
    return {name: json.loads(path.read_text(encoding="utf-8")) for name, path in FILES.items()}


def expected_by_group(doc: dict) -> dict[int, dict[int, dict]]:
    return {g["tgId"]: {t["tcId"]: t for t in g["tests"]} for g in doc["testGroups"]}


def check_case(kind: str, params: M.Params, prompt: dict, expected: dict) -> bool:
    """Ejecuta un caso y devuelve True si coincide con el resultado del NIST."""
    if kind == "keyGen":
        ek, dk = M.keygen_internal(
            params, bytes.fromhex(prompt["d"]), bytes.fromhex(prompt["z"])
        )
        return (
            ek.hex().upper() == expected["ek"]
            and dk.hex().upper() == expected["dk"]
        )

    if kind == "encapsulation":
        k, c = M.encaps_internal(
            params, bytes.fromhex(prompt["ek"]), bytes.fromhex(prompt["m"])
        )
        return k.hex().upper() == expected["k"] and c.hex().upper() == expected["c"]

    if kind == "decapsulation":
        k = M.decaps_internal(params, bytes.fromhex(prompt["dk"]), bytes.fromhex(prompt["c"]))
        return k.hex().upper() == expected["k"]

    if kind == "decapsulationKeyCheck":
        # FIPS 203, 7.3: type check + hash check.
        try:
            M.check_dk(params, bytes.fromhex(prompt["dk"]))
            accepted = True
        except M.MLKEMError:
            accepted = False
        return accepted == expected["testPassed"]

    if kind == "encapsulationKeyCheck":
        # FIPS 203, 7.2: type check + modulus check.
        try:
            M.check_ek(params, bytes.fromhex(prompt["ek"]))
            accepted = True
        except M.MLKEMError:
            accepted = False
        return accepted == expected["testPassed"]

    raise ValueError(f"tipo de caso desconocido: {kind}")


def run_category(
    kind: str, prompt_doc: dict, expected_doc: dict, stats: Stats, verbose: bool
) -> None:
    exp_by_tg = expected_by_group(expected_doc)
    total = ok = 0
    for group in prompt_doc["testGroups"]:
        gkind = group.get("function")
        if gkind is not None and gkind != kind:
            continue
        params = M.PARAMS[group["parameterSet"]]
        exp_tests = exp_by_tg[group["tgId"]]
        for prompt in group["tests"]:
            expected = exp_tests[prompt["tcId"]]
            good = check_case(kind, params, prompt, expected)
            total += 1
            ok += good
            if not good and verbose:
                print(f"  FALLO {kind} {group['parameterSet']} tcId={prompt['tcId']}")
    stats[kind] = [ok, total]
    print(f"{kind:<24} {ok:>4}/{total:<4} {'OK' if ok == total else 'FALLO'}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Validacion ACVP completa de ML-KEM (FIPS 203)")
    ap.add_argument("--verbose", action="store_true", help="muestra cada caso fallido")
    args = ap.parse_args()

    raw = load()
    stats: Stats = {}

    print("Validacion contra el conjunto completo de vectores ACVP del NIST")
    print(f"Fuente: {CACHE}")
    print()
    print(f"{'categoria':<24} {'ok':>8}  estado")
    print("-" * 44)

    run_category("keyGen", raw["keygen_prompt"], raw["keygen_expected"], stats, args.verbose)
    run_category("encapsulation", raw["encap_prompt"], raw["encap_expected"], stats, args.verbose)
    run_category("decapsulation", raw["encap_prompt"], raw["encap_expected"], stats, args.verbose)
    run_category(
        "decapsulationKeyCheck", raw["encap_prompt"], raw["encap_expected"], stats, args.verbose
    )
    run_category(
        "encapsulationKeyCheck", raw["encap_prompt"], raw["encap_expected"], stats, args.verbose
    )

    total_ok = sum(v[0] for v in stats.values())
    total = sum(v[1] for v in stats.values())
    print("-" * 44)
    print(f"{'TOTAL':<24} {total_ok:>4}/{total:<4} {'OK' if total_ok == total else 'FALLO'}")
    return 0 if total_ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""
Descarga los vectores oficiales ACVP del NIST para ML-KEM (FIPS 203) y extrae
un subconjunto compacto para las pruebas de conformidad (KAT).

Fuente oficial:
    https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
    - ML-KEM-keyGen-FIPS203/{prompt,expectedResults}.json
    - ML-KEM-encapDecap-FIPS203/{prompt,expectedResults}.json

Los vectores ACVP son la fuente de verdad usada por los laboratorios
acreditados para validar implementaciones de FIPS 203.

Uso:
    python tools/fetch_acvp_vectors.py [--per-group N]

Salida:
    tests/vectors/ml_kem_kat.json  (subconjunto + metadatos de procedencia)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import urllib.request
from datetime import datetime, timezone

BASE = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"
FILES = {
    "keygen_prompt": f"{BASE}/ML-KEM-keyGen-FIPS203/prompt.json",
    "keygen_expected": f"{BASE}/ML-KEM-keyGen-FIPS203/expectedResults.json",
    "encap_prompt": f"{BASE}/ML-KEM-encapDecap-FIPS203/prompt.json",
    "encap_expected": f"{BASE}/ML-KEM-encapDecap-FIPS203/expectedResults.json",
}
ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "vectors" / "ml_kem_kat.json"
CACHE = ROOT / "tests" / "vectors" / "_acvp_cache"


def fetch(name: str, url: str) -> tuple[bytes, str]:
    CACHE.mkdir(parents=True, exist_ok=True)
    local = CACHE / f"{name}.json"
    if local.exists():
        data = local.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=120) as resp:
            data = resp.read()
        local.write_bytes(data)
    return data, hashlib.sha256(data).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-group", type=int, default=2)
    args = ap.parse_args()

    raw: dict[str, dict] = {}
    provenance: dict[str, dict] = {}
    for name, url in FILES.items():
        data, digest = fetch(name, url)
        raw[name] = json.loads(data)
        provenance[name] = {"url": url, "sha256": digest, "bytes": len(data)}

    n = args.per_group

    kg_expected = {g["tgId"]: g for g in raw["keygen_expected"]["testGroups"]}
    keygen = []
    for group in raw["keygen_prompt"]["testGroups"]:
        exp = {t["tcId"]: t for t in kg_expected[group["tgId"]]["tests"]}
        for test in group["tests"][:n]:
            e = exp[test["tcId"]]
            keygen.append(
                {
                    "parameterSet": group["parameterSet"],
                    "tcId": test["tcId"],
                    "d": test["d"],
                    "z": test["z"],
                    "ek": e["ek"],
                    "dk": e["dk"],
                }
            )

    enc_expected = {g["tgId"]: g for g in raw["encap_expected"]["testGroups"]}
    encaps, decaps = [], []
    for group in raw["encap_prompt"]["testGroups"]:
        exp = {t["tcId"]: t for t in enc_expected[group["tgId"]]["tests"]}
        if group["function"] == "encapsulation":
            for test in group["tests"][:n]:
                e = exp[test["tcId"]]
                encaps.append(
                    {
                        "parameterSet": group["parameterSet"],
                        "tcId": test["tcId"],
                        "ek": test["ek"],
                        "m": test["m"],
                        "c": e["c"],
                        "k": e["k"],
                    }
                )
        elif group["function"] == "decapsulation":
            for test in group["tests"][:n]:
                e = exp[test["tcId"]]
                decaps.append(
                    {
                        "parameterSet": group["parameterSet"],
                        "tcId": test["tcId"],
                        "dk": test["dk"],
                        "c": test["c"],
                        "k": e["k"],
                    }
                )

    doc = {
        "description": (
            "Vectores de prueba oficiales ACVP (NIST) para ML-KEM FIPS 203. "
            "Subconjunto extraido automaticamente; no editar a mano."
        ),
        "retrieved_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_files": provenance,
        "subset_per_group": n,
        "keygen": keygen,
        "encaps": encaps,
        "decaps": decaps,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"OK -> {OUT}")
    print(f"keygen={len(keygen)} encaps={len(encaps)} decaps={len(decaps)}")


if __name__ == "__main__":
    main()

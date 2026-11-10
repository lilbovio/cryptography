# ML-KEM (FIPS 203) + AES-256-GCM — Proyecto de criptografía post-cuántica

Implementación académica y **validada contra los vectores oficiales del NIST**
del mecanismo de encapsulamiento de llaves post-cuántico **ML-KEM** (FIPS 203),
con cifrado de mensajes mediante **KEM-DEM** (AES-256-GCM + HKDF-SHA256).

## Resultado en una línea

**18/18 KAT oficiales ACVP idénticos · 240/240 casos ACVP completos
(incluidos KeyCheck) · 6/6 interoperabilidad con PQClean · 56/56 pruebas OK ·
mensaje cifrado y descifrado correctamente · alteraciones rechazadas.**

## Inicio rápido

```powershell
cd "C:\Users\user\Documents\proyectos\criptografia\algoritmo post-cuántico NIST"
python -m pip install -r requirements.txt

python src/demo.py                  # llave -> secreto -> cifrar -> descifrar
python -m unittest discover -s tests -v   # suite completa (56 pruebas)
python tools/verify_full_acvp.py    # validación ACVP completa (240 casos)
```

Salida esperada del demo: `RESULTADO: OK - mensaje identico` y
`RECHAZADO correctamente` al alterar el paquete.

## Documentos

| Documento | Contenido |
|---|---|
| **[INFORME.md](INFORME.md)** | Informe completo: norma, diseño, criterios, resultados, entorno (OpenCode v2.2.6, modelo Big Pickle), referencias |
| [docs/CRITERIOS_DE_ACEPTACION.md](docs/CRITERIOS_DE_ACEPTACION.md) | AC-01 … AC-15 con justificación y evidencia |
| [docs/CRITERIOS_DE_FALLA.md](docs/CRITERIOS_DE_FALLA.md) | F-01 … F-11: comportamiento fail-closed |

## Estructura

```text
src/ml_kem.py       FIPS 203 completo (solo biblioteca estándar)
src/hybrid.py       KEM-DEM: HKDF-SHA256 + AES-256-GCM, formato PQCH
src/demo.py         demo de la actividad + prueba negativa
tests/              56 pruebas: KAT, primitivas, integridad, fallas
tools/              descarga ACVP, verificación completa (240) y benchmark
docs/               criterios de aceptación y de falla
```

## Qué se implementó

- `ML-KEM.KeyGen`, `Encaps`, `Decaps` (Algoritmos 19, 20 y 21 de FIPS 203).
- `K-PKE.KeyGen`, `Encrypt`, `Decrypt` (Algoritmos 13, 14 y 15).
- Primitivas: ByteEncode/Decode, SampleNTT, SamplePolyCBD, NTT, NTT⁻¹,
  MultiplyNTTs, Compress/Decompress.
- Rechazo implícito, validación de llaves (§7.2/§7.3), tamaños oficiales.
- Los 3 conjuntos: ML-KEM-512, ML-KEM-768 y ML-KEM-1024.

## Requisitos

- Python 3.10+ (probado con 3.14.7).
- `cryptography` (probado con 50.0.2) para AES-256-GCM y HKDF.
- Opcional: `pqcrypto==1.0.0` para la prueba de interoperabilidad con PQClean.

## Entorno de generación

- **OpenCode:** v2.2.6
- **Modelo:** Big Pickle (`opencode` / `big-pickle`)

## Advertencia

Implementación **académica**. No es constante en tiempo, no borra secretos de
memoria y no sustituye una biblioteca validada para producción. Ver las
limitaciones en el informe (§11).

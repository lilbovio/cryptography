# Implementación de un algoritmo post-cuántico conforme a NIST: **ML-KEM (FIPS 203)**

**Actividad:** implementar un algoritmo post-cuántico según las especificaciones del NIST, generar llave y secreto, cifrar y descifrar, con criterios de aceptación y de falla documentados.
**Carrera:** Ingeniería en Ciencias Computacionales — Criptografía
**Fecha del informe:** 9 de noviembre de 2026
**Carpeta del proyecto:** `C:\Users\user\Documents\proyectos\criptografia\algoritmo post-cuántico NIST`

---

## 1. Resumen ejecutivo

Se implementó **ML-KEM**, el mecanismo de encapsulamiento de llaves
post-cuántico estandarizado por el NIST en **FIPS 203** (13 de agosto de 2024),
en sus tres conjuntos aprobados: **ML-KEM-512, ML-KEM-768 y ML-KEM-1024**.

Como un KEM no cifra mensajes arbitrarios (solo produce un secreto compartido y
su ciphertext), el cifrado de datos se realizó con la construcción estándar
**KEM-DEM**: ML-KEM para establecer la llave y **AES-256-GCM** para cifrar y
autenticar el mensaje, con derivación **HKDF-SHA256**.

### Evidencia principal

| Verificación | Resultado |
|---|---|
| Vectores oficiales ACVP del NIST (suite rápida: 18 KAT) | **18/18 idénticos byte a byte** |
| Conjunto **completo** ACVP (KeyGen, Encaps, Decaps y KeyCheck) | **240/240 correctos** |
| Interoperabilidad con PQClean en ambos sentidos (3 conjuntos) | **6/6 correctas** |
| Pruebas automatizadas (`unittest`) | **56/56 OK**, 0 fallos, 0 errores |
| Demo de llave → secreto → cifrado → descifrado | Mensaje recuperado idéntico |
| Paquete alterado | Rechazado (AES-GCM `InvalidTag` → `IntegrityError`) |
| Prueba de "cada byte autenticado" | **1156/1156** posiciones rechazadas |

La implementación de ML-KEM usa **solo la biblioteca estándar de Python**
(`hashlib` para SHA3/SHAKE). La capa simétrica usa `cryptography`, una
biblioteca auditada y ampliamente usada, únicamente para AES-256-GCM y HKDF.

---

## 2. Entorno de desarrollo y herramientas de IA

### 2.1 Versión de OpenCode

```text
$ opencode --version
v2.2.6
```

- **OpenCode:** `v2.2.6`
- **Modelo utilizado:** **Big Pickle**
  - Proveedor: `opencode`
  - Identificador del modelo: `big-pickle`
  - Nombre mostrado: Big Pickle

> Estos datos corresponden al entorno en el que se generó este proyecto. La
> versión se obtuvo ejecutando `opencode --version` y el modelo es el declarado
> por el entorno de ejecución.

### 2.2 Entorno técnico

| Componente | Versión | Uso |
|---|---|---|
| Python | 3.14.7 | Implementación y pruebas |
| Sistema operativo | Windows 11 (10.0.26300) | Plataforma de ejecución |
| `cryptography` | 50.0.2 | AES-256-GCM y HKDF-SHA256 |
| `pqcrypto` | 1.0.0 | Solo prueba de interoperabilidad (opcional) |
| `unittest` | biblioteca estándar | Marco de pruebas |
| NIST ACVP-Server | `master` (descarga 2026-11-10T05:25Z) | Vectores oficiales |

Dependencias de ejecución: `cryptography` (obligatoria). Dependencia opcional
para interoperabilidad: `pqcrypto` (si no está, esa prueba se omite).

---

## 3. Fundamento normativo (datos verificados en el PDF oficial)

Toda la información de esta sección se contrastó con el documento oficial
`NIST.FIPS.203.pdf` (56 páginas) descargado de `nvlpubs.nist.gov`, no con
resúmenes de terceros.

- **Norma:** FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism
  Standard*.
- **Publicación:** 13 de agosto de 2024. DOI: `10.6028/NIST.FIPS.203`.
- **Origen:** basada en el esquema **CRYSTALS-Kyber** presentado al concurso
  post-cuántico del NIST.
- **Componente interno:** **K-PKE**, un esquema de cifrado de llave pública
  sobre retículos (Module-LWE).
- **Anillo:** `R_q = Z_q[X]/(X^256 + 1)`, con `q = 3329`, `n = 256`.
- **Transformada:** NTT con raíz primitiva `ζ = 17`; inversa con factor
  `128⁻¹ mod q = 3303`.
- **Hash/XOF:** `G = SHA3-512`, `H = SHA3-256`, `J = SHAKE256(·, 32)`,
  `XOF = SHAKE128`, `PRF_η(s,b) = SHAKE256(s‖b, 64η)`.

### 3.1 Conjuntos de parámetros aprobados (FIPS 203, Tabla 2)

| Conjunto | k | η₁ | η₂ | d_u | d_v | Categoría de seguridad NIST |
|---|---:|---:|---:|---:|---:|---|
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 1 |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 3 |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 5 |

### 3.2 Tamaños oficiales (FIPS 203, Tabla 3)

| Conjunto | Llave de encapsulamiento (ek) | Llave de desencapsulamiento (dk) | Ciphertext (c) | Secreto |
|---|---:|---:|---:|---:|
| ML-KEM-512 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B | 32 B |

### 3.3 Tasa de fallo de desencapsulamiento (FIPS 203, Tabla 1)

| Conjunto | Tasa de fallo |
|---|---|
| ML-KEM-512 | 2^-138.8 |
| ML-KEM-768 | 2^-164.8 |
| ML-KEM-1024 | 2^-174.8 |

Esta es la probabilidad de que, aun con llaves y ciphertext válidos, el
descifrado produzca un mensaje distinto y el rechazo implícito se active. Es
despreciable por diseño.

### 3.4 Algoritmos del estándar implementados

La numeración se verificó en el índice del PDF oficial:

| Algoritmo FIPS 203 | Nombre | Función en `src/ml_kem.py` |
|---|---|---|
| 5 | `ByteEncode_d` | `byte_encode` |
| 6 | `ByteDecode_d` | `byte_decode` |
| 7 | `SampleNTT` | `sample_ntt` |
| 8 | `SamplePolyCBD_η` | `sample_poly_cbd_from_bytes` / `sample_poly_cbd_prf` |
| 9 | `NTT` | `ntt` |
| 10 | `NTT⁻¹` | `inv_ntt` |
| 11 | `MultiplyNTTs` | `multiply_ntts` |
| 12 | `BaseCaseMultiply` | `base_case_multiply` |
| 13 | `K-PKE.KeyGen` | `k_pke_keygen` |
| 14 | `K-PKE.Encrypt` | `k_pke_encrypt` |
| 15 | `K-PKE.Decrypt` | `k_pke_decrypt` |
| 16 | `ML-KEM.KeyGen_internal` | `keygen_internal` |
| 17 | `ML-KEM.Encaps_internal` | `encaps_internal` |
| 18 | `ML-KEM.Decaps_internal` | `decaps_internal` |
| 19 | `ML-KEM.KeyGen` | `MLKEM.keygen` |
| 20 | `ML-KEM.Encaps` | `MLKEM.encaps` |
| 21 | `ML-KEM.Decaps` | `MLKEM.decaps` |

### 3.5 Puntos finos del estándar que se respetaron

1. **KeyGen usa `G(d ‖ k)`** (32 bytes + 1 byte de separación de dominio), no
   directamente `d`. El byte `k` evita reutilizar semillas entre conjuntos.
2. **Layout de `dk`:**
   `dk_PKE (384k B) ‖ ek (384k+32 B) ‖ H(ek) (32 B) ‖ z (32 B)`.
3. **Encaps:** `(K, r) = G(m ‖ H(ek))` y `c = K-PKE.Encrypt(ek, m, r)`.
4. **Encrypt incluye el mensaje en `v`:**
   `v = NTT⁻¹(t̂ᵀ ∘ ŷ) + e2 + Decompress₁(ByteDecode₁(m))`.
   Omitir el último término es un error clásico; los KAT lo detectaron
   (ver §10, punto 4).
5. **Rechazo implícito:** si `c′ ≠ c`, `Decaps` devuelve
   `K̄ = J(z ‖ c)` **sin lanzar error** (Algoritmo 18).
6. **Validación de llaves (pasos exactos del estándar):**
   - §7.2 (`ek`): *type check* (`384k + 32` bytes) + *modulus check*
     (todo coeficiente de 12 bits `< q`).
   - §7.3 (`dk`): *type check* (`768k + 96` bytes) + *hash check*
     (`H(dk[384k : 768k+32])` coincide con `dk[768k+32 : 768k+64]`).
     La sección 7.3 **no** exige modulus check de `dk_PKE`; el `ek` embebido
     queda cubierto por el hash check. Añadir un rechazo extra por coeficientes
     de `dk_PKE` sería más estricto que FIPS 203 y se evitó deliberadamente.
   Matiz de §7.3: el hash check de `dk` puede hacerse una sola vez al recibir
   la llave ("need not be performed ... with every execution"), mientras que el
   *ciphertext type check* sí es obligatorio en cada `Decaps`. Por eso la API
   expone `check_dk`, el demo lo ejecuta tras `KeyGen`, y `decaps` valida
   siempre la longitud de `c`.
7. **SampleNTT** usa rechazo sobre valores de 12 bits: se aceptan solo
   `d₁, d₂ < q`; el bucle no tiene un límite fijo en el estándar (se implementó
   como lectura incremental de SHAKE128, equivalente a la definición).
8. **ByteEncode/ByteDecode** empaquetan bits en orden little-endian dentro de
   cada byte, como especifica el estándar.

---

## 4. Diseño de la solución

### 4.1 Por qué KEM + DEM

ML-KEM **no es un cifrador de mensajes**: entrega un secreto de 32 bytes y un
ciphertext de llave. Para cifrar datos se usa el patrón **KEM-DEM**, que es la
forma estándar de emplear un KEM:

```text
Emisor                                            Receptor
------                                            --------
(ek, dk) ← ML-KEM.KeyGen()                        (ek, dk)
(K, c_kem) ← ML-KEM.Encaps(ek)
key = HKDF-SHA256(K, salt=c_kem, info=...)
c_dem = AES-256-GCM(key, nonce, msg, aad=header‖c_kem)
                     ───── paquete ─────►
                                                  K′ = ML-KEM.Decaps(dk, c_kem)
                                                  key′ = HKDF-SHA256(K′, ...)
                                                  msg = AES-256-GCM.Open(...)
```

- La **confidencialidad** la aporta ML-KEM (resistente a ataques cuánticos).
- La **integridad y autenticación** del mensaje las aporta AES-256-GCM.
- El **nonce** de 96 bits es aleatorio por mensaje (`os.urandom`).
- El **AAD** incluye la cabecera y `c_kem`, lo que ata el algoritmo, los
  parámetros y el ciphertext KEM al mensaje: impide downgrades y mezclas de
  paquetes.
- `HKDF-SHA256` (RFC 5869) con `salt = c_kem` e `info` con el nombre del
  conjunto da separación de dominio y evita usar `K` directamente como llave.

### 4.2 Formato del paquete

```text
+--------+---------+----------+------------+-----------+-------------+---------------------+
| "PQCH" | version | param_id | c_kem_len  | c_kem     | nonce (12B) | AES-256-GCM ct+tag  |
| 4 B    | 1 B = 1 | 1 B      | 2 B (BE)   | variable  |             | variable            |
+--------+---------+----------+------------+-----------+-------------+---------------------+
```

- `param_id`: `1` = ML-KEM-512, `2` = ML-KEM-768, `3` = ML-KEM-1024.
- `AAD = "PQCH" ‖ version ‖ param_id ‖ c_kem_len ‖ c_kem`.
- El paquete es autocontenido: no requiere metadatos externos.
- `decrypt` valida magic, versión, `param_id`, longitud declarada y longitud
  mínima antes de tocar criptografía.

### 4.3 Elección de parámetros

La implementación soporta los tres conjuntos. El **demo usa ML-KEM-768** por
ser el recomendado habitualmente para uso general (categoría 3). La API permite
elegir cualquiera; el paquete lleva el identificador para que el receptor no
adivine.

---

## 5. Estructura del proyecto

```text
algoritmo post-cuántico NIST/
├── INFORME.md                      ← este documento
├── README.md                       ← inicio rápido e índice
├── requirements.txt                ← dependencia de ejecución
├── requirements-dev.txt            ← dependencia opcional (interoperabilidad)
├── run_tests.ps1                   ← ejecuta toda la suite
├── src/
│   ├── ml_kem.py                   ← FIPS 203 completo (solo stdlib)
│   ├── hybrid.py                   ← KEM-DEM: HKDF + AES-256-GCM
│   └── demo.py                     ← demo llave → secreto → cifrar → descifrar
├── tests/
│   ├── test_ml_kem.py              ← KAT, tamaños, primitivas, interop
│   ├── test_hybrid.py              ← roundtrip, integridad, formato
│   ├── test_failures.py            ← criterios de falla F-01…F-11
│   └── vectors/
│       ├── ml_kem_kat.json         ← subconjunto ACVP + procedencia
│       └── _acvp_cache/            ← archivos oficiales completos (caché)
├── tools/
│   ├── fetch_acvp_vectors.py       ← descarga y extrae vectores del NIST
│   ├── verify_full_acvp.py         ← validación ACVP completa (240 casos)
│   └── benchmark.py                ← medición de tiempos
├── docs/
│   ├── CRITERIOS_DE_ACEPTACION.md  ← AC-01…AC-15 en detalle
│   └── CRITERIOS_DE_FALLA.md       ← F-01…F-11 en detalle
└── salida/                         ← artefactos del demo (si se usa --guardar)
```

---

## 6. Instalación y ejecución

```powershell
cd "C:\Users\user\Documents\proyectos\criptografia\algoritmo post-cuántico NIST"

# Dependencia obligatoria (solo para AES-GCM/HKDF)
python -m pip install -r requirements.txt

# Demo completo
python src/demo.py

# Demo con otro conjunto y guardando artefactos
python src/demo.py --param ML-KEM-1024 --mensaje "prueba" --guardar

# Suite completa (56 pruebas)
python -m unittest discover -s tests -v
# o bien:
.\run_tests.ps1

# Solo criterios de falla
python -m unittest tests.test_failures -v

# Benchmark
python tools/benchmark.py

# Validacion ACVP completa (240 casos, usa la cache de tests/vectors/_acvp_cache)
python tools/verify_full_acvp.py

# Regenerar vectores ACVP (requiere red)
python tools/fetch_acvp_vectors.py --per-group 2
# Para los 25 casos por grupo:
python tools/fetch_acvp_vectors.py --per-group 25
```

---

## 7. Criterios de aceptación

> Documento detallado: `docs/CRITERIOS_DE_ACEPTACION.md`.

Un criterio se cumple **solo si su prueba pasa**. El conjunto completo son 56
pruebas; se acepta la entrega únicamente con `OK` (0 fallos, 0 errores).

| ID | Criterio | Prueba(s) | Estado |
|----|----------|-----------|--------|
| AC-01 | Parámetros y tamaños exactos de FIPS 203 (Tablas 2 y 3) | `TestParameterSizes.test_sizes` | Cumple |
| AC-02 | `KeyGen` idéntico a ACVP | `test_keygen_kat` | Cumple |
| AC-03 | `Encaps` (K y c) idéntico a ACVP | `test_encaps_kat` | Cumple |
| AC-04 | `Decaps` idéntico a ACVP | `test_decaps_kat` | Cumple |
| AC-05 | K = K′ en los 3 conjuntos y varias sesiones | `TestRoundtrip` | Cumple |
| AC-06 | Rechazo implícito correcto: K̄ = J(z‖c) | `TestImplicitRejection`, `test_F01` | Cumple |
| AC-07 | Cifrado/descifrado híbrido exacto (0 B a 1 MiB, UTF-8) | `TestHybridRoundtrip` | Cumple |
| AC-08 | Integridad total: cualquier byte alterado ⇒ rechazo | `TestDemAuthentication` | Cumple |
| AC-09 | Con `dk` incorrecta no se obtiene el mensaje | `TestWrongKeys`, `test_F03` | Cumple |
| AC-10 | Funciones internas deterministas | `TestDeterminism` | Cumple |
| AC-11 | Validación de llaves FIPS 203 §7.2/§7.3 | `TestKeyValidation`, `test_F04/F05` | Cumple |
| AC-12 | Primitivas correctas (ByteEncode/Decode, NTT, MultiplyNTTs, Compress) | `TestPrimitives` | Cumple |
| AC-13 | Interoperabilidad bidireccional con PQClean | `TestInteropPQClean` | Cumple |
| AC-14 | Formato explícito, sin texto plano, malformados rechazados | `TestPacketFormat`, `TestMalformedPackets` | Cumple |
| AC-15 | Trazabilidad de vectores (URL + SHA-256) | `test_kat_source_is_nist_acvp` | Cumple |

### Cómo leer un criterio

Ejemplo **AC-06** (el más importante criptográficamente):

- **Enunciado:** al alterar un bit de `c`, `Decaps` debe devolver
  `K̄ = SHAKE256(z‖c, 32)`, distinto de `K`, **sin lanzar excepción**.
- **Por qué:** FIPS 203 exige rechazo implícito para no crear un oráculo que
  distinga ciphertexts válidos de inválidos.
- **Verificación:** se altera `c`, se comprueba `K̄ ≠ K` y que `K̄` coincide
  exactamente con el SHAKE256 calculado de forma independiente.
- **Resultado:** pasa en los tres conjuntos.

Los 15 criterios están desarrollados con enunciado, justificación, procedimiento
y evidencia en `docs/CRITERIOS_DE_ACEPTACION.md`.

---

## 8. Criterios de falla

> Documento detallado: `docs/CRITERIOS_DE_FALLA.md`.

Principio **fail closed**: ante una entrada hostil el sistema debe fallar y no
devolver texto plano ni un secreto útil. En `tests/test_failures.py`, que una
prueba pase significa que la falla esperada ocurrió.

| ID | Entrada hostil | Respuesta obligatoria | Prohibido |
|----|----------------|-----------------------|-----------|
| F-01 | `c` del KEM alterado | `K̄ = SHAKE256(z‖c, 32)`, sin excepción, ≠ K | Devolver K o lanzar error |
| F-02 | Paquete con 1 bit alterado | `IntegrityError` / `PacketError` | Devolver texto plano |
| F-03 | `dk` de otra sesión | `IntegrityError` | Devolver texto plano |
| F-04 | `ek` con coeficiente ≥ q | `MLKEMError` | Aceptar la llave |
| F-05 | `dk` con `H(ek)` inconsistente | `MLKEMError` | Aceptar la llave |
| F-06 | Longitudes de llave incorrectas | `MLKEMError` | Aceptar/truncar |
| F-07 | Paquete de otro conjunto | `PacketError` | Degradar parámetros |
| F-08 | `plaintext` no `bytes` | Error explícito | Conversión implícita |
| F-09 | `c` con longitud no oficial | `MLKEMError` | Procesar basura |
| F-10 | Paquete truncado / sin tag | `PacketError` / `IntegrityError` | Devolver datos |
| F-11 | `magic` inválido | `PacketError` | Aceptar como válido |

Resultado: **12/12 pruebas de falla pasan** (11 criterios + 1 control positivo).

Ejemplo **F-01**: se cambia un bit de `c` en 4 posiciones; el sistema devuelve
la llave de rechazo correcta y nunca el secreto original. Esto demuestra que el
rechazo implícito no es un `try/except` cosmético, sino el comportamiento
definido por FIPS 203.

---

## 9. Resultados de la validación

### 9.1 Vectores oficiales ACVP (NIST): suite rápida

Fuente exacta (repositorio oficial del NIST):

| Archivo | URL | SHA-256 |
|---|---|---|
| `ML-KEM-keyGen-FIPS203/prompt.json` | `raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json` | `3f9ce34f6c836c77…` (64 hex) |
| `ML-KEM-keyGen-FIPS203/expectedResults.json` | ídem `expectedResults.json` | `a253d0ad91c95ebe…` |
| `ML-KEM-encapDecap-FIPS203/prompt.json` | ídem | `998e22dfb12efb14…` |
| `ML-KEM-encapDecap-FIPS203/expectedResults.json` | ídem | `9089ec6ff2424da9…` |

Los hashes completos, la fecha de descarga y los casos están registrados en
`tests/vectors/ml_kem_kat.json`
(SHA-256 del archivo: `6a4ace01c23bd4d9d2234db2b19bc0fb16421d07a7407880335e1f8f31200fbb`).

Subconjunto usado por defecto: 2 casos por grupo y operación (6 KeyGen, 6 Encaps,
6 Decaps). Los archivos completos quedan en `tests/vectors/_acvp_cache/` y el
script permite extraer los 25 casos por grupo.

**Resultado:**

```text
keygen  ML-KEM-512  1 OK      encaps  ML-KEM-512  1 OK      decaps  ML-KEM-512  76 OK
keygen  ML-KEM-512  2 OK      encaps  ML-KEM-512  2 OK      decaps  ML-KEM-512  77 OK
keygen  ML-KEM-768  26 OK     encaps  ML-KEM-768  26 OK     decaps  ML-KEM-768  86 OK
keygen  ML-KEM-768  27 OK     encaps  ML-KEM-768  27 OK     decaps  ML-KEM-768  87 OK
keygen  ML-KEM-1024 51 OK     encaps  ML-KEM-1024 51 OK     decaps  ML-KEM-1024 96 OK
keygen  ML-KEM-1024 52 OK     encaps  ML-KEM-1024 52 OK     decaps  ML-KEM-1024 97 OK
```

**18/18 coincidencias exactas.**

### 9.2 Conjunto completo ACVP (240 casos)

La suite anterior usa 2 casos por grupo para ser rápida. Además se validó el
**conjunto completo** de vectores descargados del NIST con
`tools/verify_full_acvp.py`, que cubre las cinco categorías del repositorio
ACVP, incluidos los grupos de comprobación de llaves (§7.2 y §7.3):

| Categoría ACVP | Casos | Resultado |
|---|---:|---|
| `keyGen` (3 grupos × 25) | 75 | **75/75** |
| `encapsulation` (3 × 25) | 75 | **75/75** |
| `decapsulation` (3 × 10) | 30 | **30/30** |
| `decapsulationKeyCheck` (3 × 10) | 30 | **30/30** |
| `encapsulationKeyCheck` (3 × 10) | 30 | **30/30** |
| **Total** | **240** | **240/240** |

Salida real del script:

```text
categoria                      ok  estado
--------------------------------------------
keyGen                     75/75   OK
encapsulation              75/75   OK
decapsulation              30/30   OK
decapsulationKeyCheck      30/30   OK
encapsulationKeyCheck      30/30   OK
--------------------------------------------
TOTAL                     240/240  OK
```

Los grupos **KeyCheck** son especialmente relevantes para AC-11: ACVP presenta
llaves válidas e inválidas y espera un booleano `testPassed`. Se comprobó que
la discriminación es exactamente la del estándar:

- `encapsulationKeyCheck`: las llaves con coeficientes de 12 bits `≥ q` se
  rechazan (*modulus check*, §7.2).
- `decapsulationKeyCheck`: las llaves con `H(ek)` incoherente se rechazan
  (*hash check*, §7.3). Ningún caso de este conjunto tiene coeficientes de
  `dk_PKE` fuera de rango, lo que es consistente con el texto de §7.3: ese
  chequeo no forma parte de la comprobación de `dk`.

Los 30 casos de `decapsulation` mezclan ciphertexts válidos y manipulados
(15 y 15): en los manipulados el resultado esperado es la llave de rechazo
`K̄ = SHAKE256(z‖c, 32)`, y la implementación los reproduce todos.

### 9.3 Interoperabilidad con PQClean

PQClean es una implementación en C independiente, empaquetada en `pqcrypto`
1.0.0. Se probó en ambos sentidos:

- PQClean encapsula → nuestra implementación desencapsula → **mismo K**.
- Nuestra implementación encapsula → PQClean desencapsula → **mismo K**.

Resultado: **6/6** (2 direcciones × 3 conjuntos).

Esta prueba es la evidencia más fuerte contra un error "autoconsistente": una
implementación podría cifrar y descifrar consigo misma y fallar todos los KAT;
la interoperabilidad demuestra que el formato y la aritmética son los del
estándar.

### 9.4 Suite de pruebas

```text
Ran 56 tests in 16.009s
OK
```

| Archivo | Pruebas | Qué cubre |
|---|---:|---|
| `tests/test_ml_kem.py` | 23 | KAT, tamaños, determinismo, rechazo implícito, validación, primitivas, interop |
| `tests/test_hybrid.py` | 21 | roundtrip, formato, integridad byte a byte, llaves incorrectas, malformados |
| `tests/test_failures.py` | 12 | F-01…F-11 + control positivo |
| **Total** | **56** | **0 fallos, 0 errores** |

### 9.5 Demo (salida real, ML-KEM-768)

```text
0. PARAMETROS (ML-KEM-768, FIPS 203 Tablas 2 y 3)
   k=3  eta1=2  eta2=2  du=10  dv=4
   |ek| = 1184 B   |dk| = 2400 B   |c_kem| = 1088 B
1. GENERACION DE LLAVES (ML-KEM.KeyGen) ......... ok, validación 7.2/7.3 OK
2. ENCAPSULAMIENTO (ML-KEM.Encaps) .............. K de 32 B + c_kem de 1088 B
3. CIFRADO (HKDF-SHA256 + AES-256-GCM) .......... paquete de 1155 B
4. DESENCAPSULAMIENTO (ML-KEM.Decaps) ........... K == K' → True
5. DESCIFRADO ................................... mensaje idéntico → OK
6. PRUEBA NEGATIVA .............................. paquete alterado RECHAZADO
```

### 9.6 Rendimiento (Python puro, sin optimizar)

Mediana de 15 iteraciones (Windows 11, Python 3.14.7):

| Conjunto | KeyGen | Encaps | Decaps | Encrypt | Decrypt |
|---|---:|---:|---:|---:|---:|
| ML-KEM-512 | 4.30 ms | 5.53 ms | 7.59 ms | 5.53 ms | 7.86 ms |
| ML-KEM-768 | 6.87 ms | 8.99 ms | 11.31 ms | 8.75 ms | 11.69 ms |
| ML-KEM-1024 | 10.34 ms | 12.51 ms | 16.59 ms | 12.71 ms | 17.06 ms |

Mensajes de 1 MiB con ML-KEM-768: cifrado ≈ 9.34 ms, descifrado ≈ 12.03 ms.
El costo dominante es el KEM; AES-GCM en C es muy rápido. Estos tiempos son
válidos para una práctica académica, no comparables con bibliotecas en C.

---

## 10. Trazabilidad y control de alucinaciones

Esta sección documenta cómo se evitó inventar datos o APIs.

1. **Datos normativos verificados en la fuente.** La numeración de los
   Algoritmos 5–21, los tamaños (Tabla 3), los parámetros (Tabla 2), las tasas
   de fallo (Tabla 1) y las secciones 7.2/7.3 se contrastaron extrayendo el
   texto del PDF oficial `NIST.FIPS.203.pdf`. No se citó de memoria.
2. **Vectores oficiales, no inventados.** Los 18 casos provienen del repositorio
   `usnistgov/ACVP-Server`; el JSON guarda URL y SHA-256 de cada archivo fuente.
   Cualquiera puede descargarlos y comparar.
3. **La implementación se contrastó con el estándar, no consigo misma.**
   Además de los KAT, se verificó contra PQClean (implementación independiente)
   en ambos sentidos.
4. **Un error real fue detectado y corregido gracias a los KAT.** La primera
   versión de `K-PKE.Encrypt` omitía el término del mensaje
   `Decompress₁(ByteDecode₁(m))` en `v`. El KeyGen coincidía al 100 %, pero
   Encaps fallaba. Los vectores ACVP lo revelaron; se corrigió y se volvió a
   ejecutar la suite completa. Esto demuestra que los KAT discriminan de verdad
   y que no se "ajustó" el código para que pasara una prueba trivial.
5. **APIs reales y versionadas.** `AESGCM`, `HKDF`, `hashes.SHA256` son APIs
   públicas de `cryptography` 50.0.2, verificadas ejecutando las pruebas.
   `pqcrypto.kem.ml_kem_*` se usó solo tras comprobar su API
   (`keygen`, `encaps`, `decaps`) en la versión instalada.
6. **Sin afirmaciones de seguridad no demostradas.** No se afirma que el código
   sea de grado producción ni constante en tiempo; se documenta como
   implementación académica validada funcionalmente. Ver §11.

---

## 11. Limitaciones y consideraciones de seguridad

1. **No es constante en tiempo.** La implementación en Python puro usa
   comparaciones y operaciones de precisión arbitraria; no está endurecida
   contra ataques de canal lateral (timing, caché, energía). FIPS 203 exige
   validación funcional, pero un despliegue real necesita una implementación
   constante en tiempo (por ejemplo, PQClean/liboqs).
2. **Memoria y borrado.** Python no garantiza el borrado seguro de secretos;
   `dk`, `K` y las semillas quedan en memoria y pueden acabar en el recolector
   de basura. No hay `mlock` ni zeroización.
3. **Aleatoriedad.** Se usa `os.urandom`, que en Windows es
   `BCryptGenRandom`; es adecuada. En pruebas se inyectan semillas fijas a
   propósito para reproducir KAT, lo que **no** debe hacerse en producción.
4. **Formato de paquete propio.** El contenedor `PQCH` es una decisión de
   ingeniería documentada, no un formato estandarizado por NIST. El estándar
   define el KEM, no el archivo. La construcción KEM-DEM sí sigue prácticas
   recomendadas (HKDF + AEAD).
5. **Cobertura de KAT.** La suite rápida usa 2 casos por grupo (18 en total);
   además, `tools/verify_full_acvp.py` valida los 240 casos completos,
   incluidos los grupos KeyCheck. Los archivos completos están en
   `tests/vectors/_acvp_cache/`. La suite no pretende ser una certificación
   ACVP formal.
6. **Dependencia de `cryptography`.** La capa DEM depende de una biblioteca
   externa auditada; la parte post-cuántica (ML-KEM) es stdlib puro.
7. **Uso académico.** El demo imprime el secreto compartido y puede guardar
   `dk` en disco: es material didáctico, no un gestor de llaves.

---

## 12. Conclusiones

1. Se implementó **ML-KEM (FIPS 203)** completo y conforme, en sus tres
   conjuntos, con validación **byte a byte** contra los **vectores oficiales
   ACVP del NIST** (18/18 en la suite rápida y **240/240** en el conjunto
   completo, incluidos los grupos KeyCheck de §7.2/§7.3).
2. Se implementó el flujo solicitado —**generar llave y secreto, cifrar y
   descifrar**— mediante la construcción **KEM-DEM** con AES-256-GCM y
   HKDF-SHA256, recuperando el mensaje exactamente y rechazando cualquier
   manipulación.
3. Se definieron **15 criterios de aceptación** y **11 criterios de falla**,
   todos con prueba automatizada y todos cumplidos; la suite completa es de
   **56 pruebas OK**.
4. La **interoperabilidad con PQClean** en ambos sentidos respalda que la
   implementación es correcta y no solo autoconsistente.
5. El proyecto documenta explícitamente sus límites (canal lateral, borrado de
   memoria, formato propio) y no presenta como producción lo que es una
   implementación académica validada.

---

## 13. Referencias

1. NIST. **FIPS 203**, *Module-Lattice-Based Key-Encapsulation Mechanism
   Standard*. 13 de agosto de 2024. DOI: `10.6028/NIST.FIPS.203`.
   `https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf`
2. NIST. **ACVP-Server**, vectores de prueba oficiales:
   `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files`
3. NIST. **FIPS 197**, *Advanced Encryption Standard (AES)*.
4. NIST. **SP 800-38D**, *Recommendation for Block Cipher Modes of Operation:
   Galois/Counter Mode (GCM) and GMAC*.
5. IETF. **RFC 5869**, *HMAC-based Extract-and-Expand Key Derivation Function
   (HKDF)*.
6. NIST. **SP 800-56C Rev. 2**, *Recommendation for Key-Derivation Methods in
   Key-Establishment Schemes*.
7. NIST. **FIPS 204** (ML-DSA) y **FIPS 205** (SLH-DSA), contexto de la
   familia post-cuántica (no implementados en esta actividad).
8. PQClean: `https://github.com/PQClean/PQClean` (usado vía `pqcrypto` para
   interoperabilidad).
9. NIST. **SP 800-227**, *Recommendations for Key-Encapsulation Mechanisms*
   (referenciado por FIPS 203 para el uso seguro de KEM en aplicaciones).

---

## 14. Anexos

### A. Comandos de reproducción

```powershell
cd "C:\Users\user\Documents\proyectos\criptografia\algoritmo post-cuántico NIST"
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python src/demo.py
python tools/benchmark.py
```

Salida esperada de la suite: `Ran 56 tests ... OK`.

### B. Archivos clave

| Archivo | Propósito |
|---|---|
| `src/ml_kem.py` | FIPS 203 completo, solo `hashlib` + `os` |
| `src/hybrid.py` | KEM-DEM, formato `PQCH`, errores tipados |
| `src/demo.py` | Flujo de la actividad y prueba negativa |
| `tests/test_ml_kem.py` | Conformidad y primitivas |
| `tests/test_hybrid.py` | Cifrado de mensajes e integridad |
| `tests/test_failures.py` | Criterios de falla |
| `tests/vectors/ml_kem_kat.json` | Vectores + procedencia |
| `docs/CRITERIOS_DE_ACEPTACION.md` | AC-01…AC-15 |
| `docs/CRITERIOS_DE_FALLA.md` | F-01…F-11 |

### C. Glosario mínimo

- **KEM:** mecanismo que produce un secreto compartido y un ciphertext de llave.
- **DEM:** cifrado simétrico de datos (aquí AES-256-GCM).
- **K-PKE:** esquema interno de cifrado de llave pública de ML-KEM.
- **NTT:** transformada teórica de números usada para multiplicar polinomios.
- **Rechazo implícito:** devolver una llave pseudoaleatoria cuando el ciphertext
  no es válido, sin revelar el fallo.
- **ACVP:** programa de validación de algoritmos criptográficos del NIST.

---

**Declaración final:** la implementación fue validada contra los vectores
oficiales del NIST y contra una implementación independiente; los datos
normativos citados se verificaron en el PDF oficial de FIPS 203. Las pruebas,
criterios y resultados de este informe son reproducibles con los comandos del
Anexo A.

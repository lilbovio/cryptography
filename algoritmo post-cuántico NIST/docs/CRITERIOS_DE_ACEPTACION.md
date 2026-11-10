# Criterios de aceptación — ML-KEM (FIPS 203) + AES-256-GCM

**Proyecto:** algoritmo post-cuántico conforme a NIST
**Estándar implementado:** FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (13 de agosto de 2024)
**Capa de cifrado de datos:** AES-256-GCM (NIST SP 800-38D) con derivación HKDF-SHA256 (RFC 5869)
**Ejecución de las pruebas:**

```powershell
cd "C:\Users\user\Documents\proyectos\criptografia\algoritmo post-cuántico NIST"
python -m unittest discover -s tests -v
```

Un criterio se considera **cumplido** solo si la prueba indicada pasa. El conjunto
completo son **56 pruebas**; el resultado esperado es `OK`. Cualquier `FAILED`
implica que el criterio correspondiente no se cumple y la entrega no es aceptable.

---

## 1. Tabla resumen

| ID | Criterio de aceptación | Prueba(s) | Estado |
|----|------------------------|-----------|--------|
| AC-01 | Parámetros y tamaños exactos de FIPS 203 (Tablas 2 y 3) | `test_ml_kem.TestParameterSizes.test_sizes` | Cumple |
| AC-02 | `KeyGen` idéntico a los vectores oficiales ACVP del NIST | `TestKnownAnswerVectors.test_keygen_kat` | Cumple |
| AC-03 | `Encaps` (K y c) idéntico a los vectores oficiales ACVP | `TestKnownAnswerVectors.test_encaps_kat` | Cumple |
| AC-04 | `Decaps` idéntico a los vectores oficiales ACVP | `TestKnownAnswerVectors.test_decaps_kat` | Cumple |
| AC-05 | Correctitud funcional: K = K′ en los 3 conjuntos y varias sesiones | `TestRoundtrip` (2 pruebas) | Cumple |
| AC-06 | Rechazo implícito correcto: c alterado ⇒ K̄ = J(z‖c), sin excepción | `TestImplicitRejection` (2), `test_F01` | Cumple |
| AC-07 | Cifrado/descifrado híbrido exacto (0 B a 1 MiB, UTF-8 incluido) | `TestHybridRoundtrip` (4) | Cumple |
| AC-08 | Integridad total: alterar cualquier byte del paquete ⇒ rechazo | `TestDemAuthentication` (5) | Cumple |
| AC-09 | Con llave privada incorrecta no se obtiene el mensaje | `TestWrongKeys` (2), `test_F03` | Cumple |
| AC-10 | Funciones internas deterministas con las mismas semillas | `TestDeterminism` (2) | Cumple |
| AC-11 | Validación de llaves de entrada conforme a FIPS 203 §7.2/§7.3 | `TestKeyValidation` (6), `test_F04`, `test_F05` | Cumple |
| AC-12 | Primitivas correctas: ByteEncode/Decode, NTT, MultiplyNTTs, Compress | `TestPrimitives` (5) | Cumple |
| AC-13 | Interoperabilidad bidireccional con PQClean (implementación independiente) | `TestInteropPQClean.test_interop_both_directions` | Cumple |
| AC-14 | Formato de paquete explícito, sin texto plano y rechazo de malformados | `TestPacketFormat` (3), `TestMalformedPackets` (7), `test_F10`, `test_F11` | Cumple |
| AC-15 | Trazabilidad de los vectores: URL oficial y SHA-256 registrados | `test_kat_source_is_nist_acvp` | Cumple |

---

## 2. Detalle de cada criterio

### AC-01 — Parámetros y tamaños exactos

**Enunciado.** Para cada conjunto aprobado, los tamaños de llave de
encapsulamiento (`ek`), llave de desencapsulamiento (`dk`), ciphertext (`c`) y
secreto compartido deben coincidir exactamente con FIPS 203, Tabla 3.

| Conjunto | ek | dk | c | secreto | Categoría NIST |
|----------|----|----|---|---------|----------------|
| ML-KEM-512 | 800 B | 1632 B | 768 B | 32 B | 1 |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B | 32 B | 3 |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B | 32 B | 5 |

**Cómo se verifica.** `test_sizes` genera llaves y encapsula con cada conjunto,
y compara las longitudes reales con la tabla anterior (valores tomados de la
Tabla 3 del PDF oficial de FIPS 203).

**Evidencia.** Pasa para los 3 conjuntos.

---

### AC-02 — KeyGen conforme a ACVP

**Enunciado.** Dados `d` y `z` de 32 bytes, `ML-KEM.KeyGen_internal(d, z)` debe
producir exactamente el `ek` y `dk` publicados por el NIST.

**Cómo se verifica.** `test_keygen_kat` carga `tests/vectors/ml_kem_kat.json`,
que contiene casos de los 3 conjuntos extraídos de
`usnistgov/ACVP-Server/gen-val/json-files/ML-KEM-keyGen-FIPS203`, y compara
byte a byte (hex en mayúsculas).

**Evidencia.** 6/6 casos (2 por conjunto) idénticos.

---

### AC-03 — Encaps conforme a ACVP

**Enunciado.** Dados `ek` y `m`, `ML-KEM.Encaps_internal(ek, m)` debe producir
el mismo par `(K, c)` que el NIST.

**Cómo se verifica.** `test_encaps_kat`, con vectores de
`ML-KEM-encapDecap-FIPS203` (función `encapsulation`).

**Evidencia.** 6/6 casos idénticos, incluido `K`.

---

### AC-04 — Decaps conforme a ACVP

**Enunciado.** Dados `dk` y `c`, `ML-KEM.Decaps_internal(dk, c)` debe devolver
el secreto `K` esperado (incluidos los casos de rechazo implícito que el NIST
incluye en sus vectores).

**Cómo se verifica.** `test_decaps_kat` con la función `decapsulation`.

**Evidencia.** 6/6 casos idénticos.

> Nota metodológica: los vectores ACVP de decapsulación incluyen ciphertexts
> manipulados cuyo resultado esperado es la llave de rechazo
> `K̄ = SHAKE256(z ‖ c, 32)`. Esto se comprobó porque al principio de la
> implementación, con un error en `K-PKE.Encrypt`, algunos casos "pasaban":
> eran precisamente los de rechazo implícito. El KAT completo (18 vectores) es
> el que da la señal inequívoca de conformidad.

---

### AC-05 — Correctitud funcional (K = K′)

**Enunciado.** Para los 3 conjuntos y 5 sesiones por conjunto, el receptor debe
recuperar exactamente el mismo secreto de 32 bytes que generó el emisor.

**Cómo se verifica.** `TestRoundtrip.test_roundtrip_all_sets` (15 pares de
llaves) y `test_different_sessions_differ` (dos encapsulaciones del mismo `ek`
producen `K` y `c` distintos).

**Evidencia.** 15/15 y 1/1.

---

### AC-06 — Rechazo implícito

**Enunciado.** Si un atacante modifica `c`, `Decaps` **no debe lanzar error ni
devolver el secreto original**: debe devolver una llave de rechazo
`K̄ = J(z ‖ c)`, donde `J(·) = SHAKE256(·, 32)` y `z` es la semilla de
rechazo almacenada en `dk`. Esto es obligatorio en FIPS 203 (Algoritmo 18).

**Cómo se verifica.** `test_tampered_ciphertext_yields_rejection_key` (los 3
conjuntos; se comprueba `K̄ ≠ K` y `K̄ = SHAKE256(z‖c_alterado)`) y
`test_rejection_key_is_stable` (determinismo del rechazo). `test_F01` repite la
comprobación en 4 posiciones del ciphertext.

**Evidencia.** Pasa en los 3 conjuntos y 4 posiciones.

---

### AC-07 — Cifrado/descifrado híbrido exacto

**Enunciado.** El mensaje recuperado debe ser byte a byte igual al original,
para tamaños de 0 B, 1 B, 15 B, 16 B, 1000 B, texto UTF-8 y mensajes de hasta
1 MiB (benchmark).

**Cómo se verifica.** `TestHybridRoundtrip` (4 pruebas) sobre los 3 conjuntos.

**Evidencia.** Pasa; el benchmark confirma 1 MiB sin cambios.

**Justificación.** ML-KEM es un KEM: no cifra mensajes. El cifrado de datos se
hace con KEM-DEM (ML-KEM + AES-256-GCM), que es la construcción recomendada
por el NIST para usar un KEM.

---

### AC-08 — Integridad total del paquete

**Enunciado.** Cambiar un solo bit en **cualquier** byte del paquete
(cabecera, `c_kem`, nonce o ciphertext/tag) debe provocar rechazo
(`IntegrityError` o `PacketError`), nunca devolver texto plano.

**Cómo se verifica.**
- `test_every_byte_is_authenticated`: recorre las 1156 posiciones de un paquete
  de ML-KEM-768 con un mensaje de 17 B y falla si alguna modificación es
  aceptada.
- `test_tag_tamper`, `test_nonce_tamper`, `test_kem_ciphertext_tamper`,
  `test_wrong_aad`: casos específicos por región.
- `test_F02`: 5 posiciones representativas.

**Evidencia.** 1156/1156 posiciones rechazadas.

**Fundamento.** AES-GCM autentica con un tag de 128 bits; además el AAD incluye
la cabecera y `c_kem`, de modo que un cambio de parámetro o de ciphertext KEM
también invalida la autenticación.

---

### AC-09 — Confidencialidad ante llave incorrecta

**Enunciado.** Con un `dk` de otra sesión, `decrypt` debe fallar con
`IntegrityError` y no devolver nada del mensaje.

**Cómo se verifica.** `test_wrong_decapsulation_key` y `test_F03`.

**Evidencia.** Pasa.

---

### AC-10 — Determinismo de las funciones internas

**Enunciado.** `KeyGen_internal(d,z)` y `Encaps_internal(ek,m)` deben ser
funciones deterministas (misma entrada ⇒ misma salida). La aleatoriedad solo
entra por `d`, `z`, `m` y el nonce, tal como define FIPS 203.

**Cómo se verifica.** `test_keygen_deterministic` y `test_encaps_deterministic`.

**Evidencia.** Pasa. Esto es lo que permite reproducir los KAT.

---

### AC-11 — Validación de llaves de entrada

**Enunciado.** Se deben implementar las comprobaciones de FIPS 203:
- §7.2 *Encapsulation key check*: **type check** (longitud `384k + 32`) y
  **modulus check** (todo coeficiente de 12 bits < q = 3329).
- §7.3 *Decapsulation key check*: **type check** (longitud `768k + 96`) y
  **hash check** (`H(dk[384k : 768k+32])` coincide con
  `dk[768k+32 : 768k+64]`). La sección 7.3 **no** pide modulus check de
  `dk_PKE`; añadirlo sería más estricto que el estándar.
  FIPS 203 permite que el hash check de `dk` se haga una sola vez al recibir la
  llave y no en cada `Decaps`; el *ciphertext type check* sí se hace siempre.

**Cómo se verifica.** `TestKeyValidation` (6 pruebas): llaves válidas aceptadas;
longitud incorrecta, coeficiente ≥ q en `ek` y hash inconsistente en `dk`
rechazados con `MLKEMError`; `encaps` rechaza un `ek` no canónico. `test_F04` y
`test_F05` repiten los casos críticos. Además, `tools/verify_full_acvp.py`
contrasta `check_ek` y `check_dk` con los 60 casos oficiales
`encapsulationKeyCheck` / `decapsulationKeyCheck` de ACVP.

**Evidencia.** 6/6 + 2/2 en la suite y **60/60** casos KeyCheck de ACVP.

---

### AC-12 — Correctitud de las primitivas

**Enunciado.** Las piezas internas deben ser correctas de forma independiente:
- `ByteEncode_d` / `ByteDecode_d` para d = 1..12 (ida y vuelta).
- `NTT` / `NTT⁻¹` (ida y vuelta).
- `MultiplyNTTs` debe coincidir con la multiplicación negacíclica escolar
  módulo q (verificación matemática independiente).
- `Compress_d` dentro de rango y `Decompress_d` con error de redondeo acotado.

**Cómo se verifica.** `TestPrimitives` (5 pruebas).

**Evidencia.** Pasa.

---

### AC-13 — Interoperabilidad con una implementación independiente

**Enunciado.** Los secretos y ciphertexts deben ser interoperables con PQClean
(implementación en C ampliamente usada, vía el paquete `pqcrypto`), en ambos
sentidos:
1. PQClean encapsula → nuestra implementación desencapsula y obtiene el mismo K.
2. Nuestra implementación encapsula → PQClean desencapsula y obtiene el mismo K.

**Cómo se verifica.** `test_interop_both_directions` para los 3 conjuntos. Si
`pqcrypto` no está instalado, la prueba se omite (no se falsea el resultado).

**Evidencia.** 6/6 comparaciones correctas.

Esto descarta errores compensados que pudieran pasar los KAT por casualidad y
demuestra que la implementación no es "autoconsistente pero incorrecta".

---

### AC-14 — Formato de paquete y entradas malformadas

**Enunciado.** El paquete debe ser explícito y verificable: `magic` `PQCH`,
versión 1, identificador de conjunto, longitud de `c_kem`, `c_kem`, nonce de
12 B y ciphertext GCM con tag. Además:
- el texto plano no debe aparecer en el paquete;
- dos cifrados del mismo mensaje deben diferir (nonce aleatorio);
- paquetes vacíos, truncados, con magic/versión/longitud/parámetro incorrectos
  deben rechazarse con `PacketError`.

**Cómo se verifica.** `TestPacketFormat` (3) y `TestMalformedPackets` (7), más
`test_F10` y `test_F11`.

**Evidencia.** 12/12.

---

### AC-15 — Trazabilidad de los vectores

**Enunciado.** El archivo de vectores debe declarar las URL oficiales y el
SHA-256 de los cuatro archivos fuente, de modo que cualquier persona pueda
reproducir la validación.

**Cómo se verifica.** `test_kat_source_is_nist_acvp` comprueba que las URL
pertenecen a `usnistgov/ACVP-Server` y que hay 4 hashes SHA-256.

**Evidencia.** Pasa. Los hashes están en `tests/vectors/ml_kem_kat.json` y se
reproducen en el informe.

---

## 3. Criterio global de aceptación

La entrega se acepta si y solo si:

1. `python -m unittest discover -s tests -v` termina con `OK` y 56 pruebas
   ejecutadas (0 fallos, 0 errores, 0 omisiones inesperadas).
2. Las 18 comparaciones KAT de la suite rápida (6 keygen + 6 encaps + 6 decaps)
   coinciden byte a byte con los vectores del NIST.
3. `python tools/verify_full_acvp.py` termina con `TOTAL 240/240 OK`, incluidos
   los 60 casos de comprobación de llaves (§7.2/§7.3).
4. La interoperabilidad con PQClean pasa en ambos sentidos para los 3
   conjuntos.
5. El demo `python src/demo.py` imprime `RESULTADO: OK - mensaje identico` y
   rechaza el paquete alterado.

Todo lo anterior se cumple en la ejecución registrada en `INFORME.md`.

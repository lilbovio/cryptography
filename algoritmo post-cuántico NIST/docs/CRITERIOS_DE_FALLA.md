# Criterios de falla — comportamiento esperado ante entradas hostiles

**Proyecto:** ML-KEM (FIPS 203) + AES-256-GCM
**Principio:** *fail closed*. Ante manipulación, llave incorrecta o entrada
inválida, el sistema **debe fallar** y **nunca** devolver texto plano, un
secreto útil ni un resultado parcial.

**Ejecución:**

```powershell
cd "C:\Users\user\Documents\proyectos\criptografia\algoritmo post-cuántico NIST"
python -m unittest tests.test_failures -v
```

En este archivo, que una prueba **pase** significa que la falla esperada
**ocurrió**. Una prueba que falle significa que el sistema aceptó una entrada
que debía rechazar: en ese caso el criterio de falla **no** se cumple.

---

## 1. Tabla resumen

| ID | Entrada hostil | Respuesta esperada (obligatoria) | Respuesta prohibida | Prueba |
|----|----------------|----------------------------------|---------------------|--------|
| F-01 | `c` del KEM alterado | `K̄ = SHAKE256(z‖c, 32)`, sin excepción, `K̄ ≠ K` | Devolver `K` original o lanzar una excepción genérica | `test_F01` |
| F-02 | Paquete híbrido con 1 bit alterado | `IntegrityError` o `PacketError`, sin dato | Devolver texto plano | `test_F02` |
| F-03 | `dk` de otra sesión | `IntegrityError` | Devolver texto plano o un texto "parecido" | `test_F03` |
| F-04 | `ek` con coeficiente ≥ q (no canónica) | `MLKEMError` antes de encapsular | Aceptar la llave y producir un ciphertext | `test_F04` |
| F-05 | `dk` con `H(ek)` inconsistente | `MLKEMError` | Aceptar la llave | `test_F05` |
| F-06 | Longitudes de llave incorrectas | `MLKEMError` explícito | Indexar fuera de rango o aceptar | `test_F06` |
| F-07 | Paquete de otro conjunto (p. ej. 512 en instancia 768) | `PacketError` | Degradar el parámetro silenciosamente | `test_F07` |
| F-08 | `plaintext` que no es `bytes` | Error explícito | Convertir implícitamente o aceptar | `test_F08` |
| F-09 | `c` con longitud distinta a la oficial | `MLKEMError` | Procesar basura o aceptar | `test_F09` |
| F-10 | Paquete truncado / sin tag | `PacketError` o `IntegrityError` | Devolver texto plano | `test_F10` |
| F-11 | `magic` distinto de `PQCH` | `PacketError` | Interpretarlo como paquete válido | `test_F11` |

---

## 2. Detalle y justificación

### F-01 — Ciphertext KEM alterado (rechazo implícito)

**Qué se hace.** Se toma un `(K, c)` válido y se cambia un bit de `c` en 4
posiciones (inicio, tercio, mitad, final).

**Qué debe ocurrir.** `Decaps` **no lanza excepción** y devuelve exactamente
`K̄ = SHAKE256(z ‖ c, 32)`, con `K̄ ≠ K`. Este es el *implicit rejection* de
FIPS 203, Algoritmo 18: el estándar exige que el descifrado no revele si el
ciphertext era válido. Devolver el `K` original o abortar con un error
distinguible serían fallas de seguridad (oráculo de descifrado).

**Qué está prohibido.** Devolver `K`, devolver un valor distinto de `K̄`, o
lanzar una excepción.

**Por qué importa.** Sin rechazo implícito, un atacante activo podría
distinguir ciphertexts válidos de inválidos y montar ataques de oráculo.

---

### F-02 — Paquete híbrido alterado

**Qué se hace.** Se modifican bits en cabecera, `c_kem`, nonce y tag.

**Qué debe ocurrir.** `IntegrityError` (fallo del tag GCM) o `PacketError`
(estructura inválida). El mensaje **no** se devuelve.

**Qué está prohibido.** Devolver texto plano, total o parcial.

**Cobertura extra.** `test_every_byte_is_authenticated` prueba las 1156
posiciones de un paquete real, no solo una muestra.

---

### F-03 — Llave privada incorrecta

**Qué se hace.** Se cifra con `ek₁` y se descifra con `dk₂` (otra sesión).

**Qué debe ocurrir.** `IntegrityError`, porque el KEM produce un secreto
distinto y AES-GCM no valida el tag.

**Qué está prohibido.** Devolver texto plano o un mensaje "aproximado".

---

### F-04 — Llave de encapsulamiento no canónica

**Qué se hace.** Se fuerza el primer coeficiente de 12 bits de `ek` al valor
`q = 3329` (patrón de bits `0xD01`).

**Qué debe ocurrir.** `check_ek` y `encaps` lanzan `MLKEMError` (FIPS 203,
§7.2, *modulus check*: todo coeficiente debe ser `< q`).

**Qué está prohibido.** Aceptar la llave: codificaciones no canónicas permiten
ambigüedad y ataques de maleabilidad.

---

### F-05 — Llave de desencapsulamiento con hash inconsistente

**Qué se hace.** Se corrompe el campo `H(ek)` almacenado dentro de `dk`
(posición `768·k + 32`).

**Qué debe ocurrir.** `check_dk` lanza `MLKEMError` (FIPS 203, §7.3, *hash
check*).

**Qué está prohibido.** Aceptar la llave y usarla.

---

### F-06 — Longitudes incorrectas

**Qué se hace.** Se pasan `ek` y `dk` con un byte de menos, y un `c` de 10
bytes.

**Qué debe ocurrir.** `MLKEMError` con mensaje claro antes de procesar.

**Qué está prohibido.** Aceptar, truncar o indexar fuera de rango.

---

### F-07 — Sin degradación de parámetros (anti-downgrade)

**Qué se hace.** Se intenta descifrar un paquete de ML-KEM-512 con una
instancia ML-KEM-768 y viceversa.

**Qué debe ocurrir.** `PacketError` por `param_id` incompatible.

**Qué está prohibido.** Reinterpretar el paquete con otro conjunto de
parámetros.

---

### F-08 — Tipo de mensaje inválido

**Qué se hace.** `encrypt(ek, "texto, no bytes")`.

**Qué debe ocurrir.** Error explícito de tipo.

**Qué está prohibido.** Conversiones implícitas silenciosas que puedan cambiar
la semántica del mensaje.

---

### F-09 — Ciphertext con longitud incorrecta

**Qué se hace.** `decaps` con `c` de 0, 1, `ct_bytes − 1` y `ct_bytes + 1`
bytes, para los 3 conjuntos.

**Qué debe ocurrir.** `MLKEMError` explícito.

**Qué está prohibido.** Procesar longitudes no oficiales (podría derivar en
comportamiento indefinido).

---

### F-10 — Paquete truncado o sin tag

**Qué se hace.** Se eliminan 1, 16, 17 y `len/2` bytes del paquete.

**Qué debe ocurrir.**
- Si el paquete queda por debajo del mínimo estructural: `PacketError`.
- Si el recorte afecta al ciphertext/tag: `IntegrityError`.

En ambos casos el rechazo es seguro y no se devuelve texto plano.

**Qué está prohibido.** Aceptar un paquete sin tag o devolver datos parciales.

---

### F-11 — Magic inválido

**Qué se hace.** Se reemplaza `PQCH` por `FAIL`.

**Qué debe ocurrir.** `PacketError`.

**Qué está prohibido.** Interpretar datos arbitrarios como un paquete.

---

## 3. Relación con los criterios de aceptación

Los criterios de falla son el complemento negativo de los de aceptación:
- AC-06 exige que el rechazo implícito sea **correcto** (F-01).
- AC-08 exige que la autenticación cubra **todo** el paquete (F-02, F-10, F-11).
- AC-09 exige confidencialidad con llave incorrecta (F-03).
- AC-11 exige validación de llaves (F-04, F-05, F-06, F-09).
- AC-14 exige formato estricto y rechazo de malformados (F-07, F-08, F-10, F-11).

Si una prueba de `tests/test_failures.py` falla, **no se cumple** el criterio de
aceptación correspondiente, aunque el resto del sistema funcione.

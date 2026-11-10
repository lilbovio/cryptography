# Cifrado Afín en Python: funcionalidad y salidas

Documentación de `cifrado_afin.py` (herramienta) y `test_cifrado_afin.py` (pruebas unitarias).

---

## 1. Resumen

El programa implementa el **cifrado afín** sobre el alfabeto de 26 letras (A–Z), con dos operaciones:

| Operación   | Fórmula                    | Función                          |
|-------------|----------------------------|----------------------------------|
| Cifrado     | `E(x) = (a·x + b) mod 26`  | `cifrar(mensaje, a, b)`          |
| Descifrado  | `D(y) = a⁻¹·(y − b) mod 26`| `descifrar(criptograma, a, b)`   |

Antes de operar, verifica que **gcd(a, 26) = 1**. Esa condición garantiza que `a` tenga inverso multiplicativo módulo 26 y, por tanto, que el mensaje se pueda recuperar.

### Archivos

| Archivo                | Contenido                                            |
|------------------------|------------------------------------------------------|
| `cifrado_afin.py`      | Funciones del cifrado y menú interactivo por consola |
| `test_cifrado_afin.py` | 41 pruebas unitarias con `unittest`                  |
| `README_cifrado_afin.md` | Este documento                                     |

### Requisitos y ejecución

Solo se necesita Python 3 (no hay dependencias externas).

```bash
python cifrado_afin.py               # programa interactivo
python test_cifrado_afin.py -v       # pruebas con detalle
python -m unittest test_cifrado_afin # pruebas, salida resumida
```

---

## 2. Reglas de tratamiento del texto

| Tipo de carácter                        | Qué hace el programa                                  |
|-----------------------------------------|-------------------------------------------------------|
| Letras `A–Z`                            | Se transforman (x = posición 0–25: A=0, B=1, …, Z=25)|
| Letras `a–z`                            | Se transforman y **se conserva la minúscula**         |
| Mayúsculas                              | Se transforman y **se conserva la mayúscula**         |
| Espacios, dígitos, signos, saltos de línea | Se dejan **sin cambios**                           |
| `Ñ`, `á`, `é`, `í`, `ó`, `ú`, `ü`       | Se dejan **sin cambios** (no pertenecen al alfabeto A–Z) |

Por eso la salida siempre tiene **la misma longitud** que la entrada.

---

## 3. Funciones del módulo `cifrado_afin.py`

### `M = 26`
Constante con el tamaño del alfabeto (el módulo `m`).

### `mcd(a, b) -> int`
Máximo común divisor con el algoritmo de Euclides.

- **Entrada:** dos enteros.
- **Salida:** entero ≥ 0 con el gcd.
- **Ejemplos:** `mcd(5, 26) = 1`, `mcd(13, 26) = 13`, `mcd(4, 26) = 2`, `mcd(0, 26) = 26`.

### `inverso_modular(a, m) -> int`
Calcula `a⁻¹ mod m` con el **algoritmo extendido de Euclides**.

- **Entrada:** `a` (entero, puede ser mayor que `m`; se reduce con `a % m`) y `m`.
- **Salida:** entero `x` en el rango `0 … m−1` tal que `a·x ≡ 1 (mod m)`.
- **Error:** lanza `ValueError("<a> no tiene inverso módulo <m>")` si `gcd(a, m) ≠ 1`.

**Idea:** el algoritmo encuentra enteros `x, y` tales que `a·x + m·y = gcd(a, m)`. Si el gcd es 1, al tomar mod `m` el término `m·y` desaparece y queda `a·x ≡ 1`, así que `x` es el inverso.

**Variables del código:**

| Variable   | Significado                                        |
|------------|----------------------------------------------------|
| `r0, r1`   | Residuos sucesivos (empiezan en `m` y `a mod m`)   |
| `t0, t1`   | Coeficiente de `a` asociado a cada residuo (empiezan en 0 y 1) |
| `q`        | Cociente entero `r0 // r1`                         |

**Traza para `a = 5`, `m = 26`:**

| Paso    | q | r0 | r1 | t0 | t1  |
|---------|---|----|----|----|-----|
| inicio  | – | 26 | 5  | 0  | 1   |
| 1       | 5 | 5  | 1  | 1  | −5  |
| 2       | 5 | 1  | 0  | −5 | 26  |

Cuando `r1 = 0` el ciclo termina y `r0 = 1` (el gcd es 1, hay inverso). El resultado es `t0 % 26 = −5 % 26 = 21`.
Verificación: `5 · 21 = 105 = 4·26 + 1 ≡ 1 (mod 26)` ✓

**Tabla de todos los inversos mod 26:**

| a     | 1 | 3 | 5  | 7  | 9 | 11 | 15 | 17 | 19 | 21 | 23 | 25 |
|-------|---|---|----|----|---|----|----|----|----|----|----|----|
| a⁻¹   | 1 | 9 | 21 | 15 | 3 | 19 | 7  | 23 | 11 | 5  | 17 | 25 |

### `validar_clave(a, m=26) -> None`
Verifica `gcd(a, m) = 1`.

- **Salida:** no devuelve nada si la clave es válida.
- **Error:** lanza `ValueError` con el mensaje
  `Clave inválida: gcd(<a>, 26) = <g> ≠ 1. El cifrado no sería invertible.`

Con m = 26 hay **12 valores válidos** de `a` entre 1 y 25: `1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`.
Son **inválidos** los pares, el 13 y el 0 (14 valores en el rango 0–25). El coeficiente `b` puede ser cualquier entero, no tiene restricción.

### `_transformar(texto, f) -> str`
Función interna (el guion bajo indica uso interno). Recorre el texto carácter por carácter:

1. Si el carácter es una letra A–Z (mayúscula o minúscula), calcula `x = ord(c) − base`, aplica `f(x) % 26` y reconstruye la letra con la misma capitalización.
2. Si no, copia el carácter tal cual.

Al aplicar `% 26` sobre el resultado, funcionan también `b` negativo, `b ≥ 26` y `a ≥ 26`.

### `cifrar(mensaje, a, b) -> str`
Valida la clave y aplica `f(x) = a·x + b`. Devuelve el criptograma.

### `descifrar(criptograma, a, b) -> str`
Valida la clave, calcula `a⁻¹` con `inverso_modular` y aplica `f(y) = a⁻¹·(y − b)`. Devuelve el mensaje original.

### `main() -> None`
Menú interactivo por consola. Pide, en orden:

1. Operación: `c` (cifrar) o `d` (descifrar).
2. Coeficiente `a` (entero).
3. Coeficiente `b` (entero).
4. Mensaje o criptograma (texto).

---

## 4. Todas las salidas del programa

Estas son las salidas reales obtenidas al ejecutar `python cifrado_afin.py`. En todos los casos se imprime primero el encabezado `=== Cifrado afín (m = 26) ===`.

### 4.1 Cifrado exitoso
```
¿Cifrar (c) o descifrar (d)? c
Coeficiente multiplicativo a: 5
Coeficiente de desplazamiento b: 8
Mensaje: Hola Mundo
Mensaje cifrado: Rali Qevxa
```

### 4.2 Descifrado exitoso
Antes del resultado se muestra el inverso calculado, útil para verificar.
```
¿Cifrar (c) o descifrar (d)? d
Coeficiente multiplicativo a: 5
Coeficiente de desplazamiento b: 8
Mensaje: Rali Qevxa
(a^-1 mod 26 = 21)
Mensaje descifrado: Hola Mundo
```

### 4.3 Clave inválida al cifrar (gcd ≠ 1)
```
¿Cifrar (c) o descifrar (d)? c
Coeficiente multiplicativo a: 13
Coeficiente de desplazamiento b: 8
Mensaje: Hola
Error: Clave inválida: gcd(13, 26) = 13 ≠ 1. El cifrado no sería invertible.
```

### 4.4 Clave inválida al descifrar
Como la línea del inverso se imprime antes de validar, aparece un guion largo `—` en lugar del número, seguido del error.
```
¿Cifrar (c) o descifrar (d)? d
Coeficiente multiplicativo a: 4
Coeficiente de desplazamiento b: 8
Mensaje: Hola
(a^-1 mod 26 = —)
Error: Clave inválida: gcd(4, 26) = 2 ≠ 1. El cifrado no sería invertible.
```

### 4.5 Opción de operación no válida
```
¿Cifrar (c) o descifrar (d)? x
Coeficiente multiplicativo a: 5
Coeficiente de desplazamiento b: 8
Mensaje: Hola
Opción no válida. Usa 'c' o 'd'.
```
Nota: el programa pide `a`, `b` y el mensaje antes de avisar que la opción es inválida.

### 4.6 `a` o `b` no son números enteros
```
¿Cifrar (c) o descifrar (d)? c
Coeficiente multiplicativo a: abc
Error: invalid literal for int() with base 10: 'abc'
```
Este mensaje lo genera Python (`int()`), por eso aparece en inglés. El programa termina de forma controlada, sin traceback.

### Resumen de salidas

| Situación                         | Salida                                                        |
|-----------------------------------|---------------------------------------------------------------|
| Cifrado correcto                  | `Mensaje cifrado: <criptograma>`                              |
| Descifrado correcto               | `(a^-1 mod 26 = <n>)` y `Mensaje descifrado: <mensaje>`       |
| `gcd(a, 26) ≠ 1`                  | `Error: Clave inválida: gcd(a, 26) = g ≠ 1. …`                |
| Opción distinta de `c`/`d`        | `Opción no válida. Usa 'c' o 'd'.`                            |
| `a` o `b` no enteros              | `Error: invalid literal for int() with base 10: '…'`          |

---

## 5. Ejemplo paso a paso

Cifrar `HOLA` con `a = 5`, `b = 8`:

| Letra | x  | 5x + 8 | mod 26 | Cifrada |
|-------|----|--------|--------|---------|
| H     | 7  | 43     | 17     | R       |
| O     | 14 | 78     | 0      | A       |
| L     | 11 | 63     | 11     | L       |
| A     | 0  | 8      | 8      | I       |

Resultado: `RALI`.

Descifrar `R` (y = 17) con `a⁻¹ = 21`: `21·(17 − 8) = 189`, y `189 mod 26 = 7` → `H` ✓

---

## 6. Relación con el cifrado César

César es el caso particular **a = 1** del cifrado afín:

```
E(x) = (1·x + b) mod 26 = (x + b) mod 26
```

Con `a = 1` desaparece la parte multiplicativa y queda una **traslación pura** de `b` posiciones. Además `gcd(1, m) = 1` siempre, así que `a = 1` es válido para cualquier alfabeto, y su inverso es `1⁻¹ = 1`.

```python
cifrar("ATAQUE", 1, 3)     # 'DWDTXH'   (César con desplazamiento 3)
descifrar("DWDTXH", 1, 3)  # 'ATAQUE'
```

Otros casos especiales:

- `a = 1, b = 0`: identidad (el texto no cambia).
- `a = 25, b = 25`: cifrado **Atbash** (A↔Z, B↔Y, …). Es su propia inversa: `cifrar("ABC", 25, 25) = "ZYX"`.

---

## 7. Salidas de las pruebas unitarias

### 7.1 Formato de la salida

| Modo                                  | Cómo se ve                                                     |
|---------------------------------------|----------------------------------------------------------------|
| Normal (`python -m unittest …`)       | Un punto `.` por prueba que pasa                               |
| Detallado (`-v`)                      | Una línea por prueba: `nombre (clase.método) ... ok`           |
| Todo bien                             | `Ran 41 tests in 0.0xxs` y `OK`                                |
| Alguna falla                          | `F` (fallo de aserción) o `E` (error inesperado), luego `FAILED (failures=N)` |

Salida esperada cuando todo funciona:

```
.........................................
----------------------------------------------------------------------
Ran 41 tests in 0.014s

OK
```

Cuando una prueba falla, `unittest` imprime el nombre de la prueba, el valor esperado y el obtenido (`AssertionError: 'X' != 'Y'`). Con eso se ubica el error. Las comprobaciones con `subTest` indican además los parámetros exactos que fallaron (por ejemplo `a=7, b=3`).

### 7.2 Qué prueba cada clase (41 pruebas)

| Clase                 | Pruebas | Qué verifica                                                                                     |
|-----------------------|:-------:|--------------------------------------------------------------------------------------------------|
| `TestMCD`             | 3       | Casos conocidos, gcd con 0, conmutatividad                                                       |
| `TestInversoModular`  | 6       | Tabla de inversos mod 26, `a·a⁻¹ ≡ 1`, rango 0…m−1, otros módulos (7, 10, 40), `a > m`, error sin inverso |
| `TestValidarClave`    | 4       | 12 claves válidas pasan, 14 inválidas lanzan `ValueError`, mensaje informativo, `cifrar`/`descifrar` validan |
| `TestCifrar`          | 14      | Vectores conocidos, una letra, identidad, Atbash, `b` y `a` fuera de rango, `b` negativo, mayúsculas/minúsculas, símbolos, cadena vacía, misma longitud, Ñ y acentos |
| `TestDescifrar`       | 6       | Vectores conocidos, una letra, Atbash, formato conservado, cadena vacía                          |
| `TestIdaYVuelta`      | 4       | `descifrar(cifrar(x)) == x` para las 312 claves válidas (12 × 26), texto largo, el cifrado cambia el texto, el cifrado es una permutación del alfabeto |
| `TestCasoCesar`       | 4       | Afín con `a = 1` equivale a César para los 26 desplazamientos, ejemplo clásico de desplazamiento 3, inverso de 1 |

### 7.3 Vectores de prueba conocidos

| Entrada          | a | b | Salida esperada                  |
|------------------|---|---|----------------------------------|
| `AFFINECIPHER`   | 5 | 8 | `IHHWVCSWFRCP`                   |
| `Hola Mundo, criptografia 2026` | 5 | 8 | `Rali Qevxa, spwfzampihwi 2026` |
| `ATAQUE`         | 1 | 3 | `DWDTXH`                         |
| `ABC`            | 25| 25| `ZYX`                            |

---

## 8. Limitaciones

- El alfabeto es **A–Z (m = 26)**. La `Ñ` y las vocales acentuadas no se cifran. Para incluirlas habría que cambiar el alfabeto (por ejemplo m = 27) y ajustar `M`, la tabla de inversos y los vectores de prueba.
- Si `a` o `b` no son enteros, el mensaje de error viene de Python y está en inglés.
- El cifrado afín es un cifrado clásico y **no es seguro**: solo hay 12 × 26 = 312 claves posibles, así que se rompe por fuerza bruta o análisis de frecuencias. Su valor es didáctico.

---

## 9. Prompts utilizados

Primer prompt:
Para mi clase de criptografia en la carrera de Ingenieria en Ciencias Computacionales debo resolver un cifado afin, que tiene como objetivo lo siguiente:
Objetivo: Desarrollar una herramienta programática capaz de ejecutar el algoritmo de cifrado afín en sus dos vertientes (cifrado y descifrado) y comprender su relación jerárquica con el cifrado César.1. Requerimientos de Programación
Deberá implementar las siguientes funciones utilizando cualquier lenguaje de programación:

* Cifrado: Aplicar la función E(x) = (ax + b) mod m.
* Descifrado: Aplicar la función inversa D(y) = a^{-1}(y
* b) mod m, donde a^{-1} es el inverso multiplicativo modular de a respecto a m.
* Validación de Clave: El programa debe verificar que gcd(a, m) = 1 antes de proceder, garantizando que el mensaje sea recuperable.
2. Entradas y Salidas
* Inputs:
* Coeficiente multiplicativo a.
* Coeficiente de desplazamiento b.
* Mensaje (texto plano para cifrar o criptograma para descifrar)

Para construir la herramienta que cumpla con esos requerimientos los outputs deben de ser
Outputs:

* Mensaje procesado (cifrado o descifrado según corresponda).
3. Análisis Teórico: El Caso César
Como parte del reporte, explique brevemente por qué el cifrado César se considera un caso particular del cifrado Afín.

En las mismas tareas se especifica una pista la cual es:
Pista: Identifique qué valor debe tomar el parámetro a para que la transformación lineal se convierta en una traslación pura.

Al final de esta practica yo debo ser capaz de explicar brevemente cómo funciona el cálculo del inverso modular a^-1 en el código generado.

Segundo prompt:
Genera el archivo de python para generar pruebas unitarias de codigo al cifrado para ponerlo a test y debuggear si es necesario

---
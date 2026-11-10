"""
Cifrado afín: E(x) = (a*x + b) mod m      D(y) = a^-1 * (y - b) mod m

Alfabeto: A-Z (m = 26). Los caracteres que no son letras (espacios,
números, signos) se dejan igual. Las mayúsculas/minúsculas se conservan.
"""

M = 26  # tamaño del alfabeto


def mcd(a: int, b: int) -> int:
    """Máximo común divisor (algoritmo de Euclides)."""
    while b != 0:
        a, b = b, a % b
    return abs(a)


def inverso_modular(a: int, m: int) -> int:
    """
    Calcula a^-1 mod m con el algoritmo extendido de Euclides.

    Buscamos x tal que a*x ≡ 1 (mod m). El algoritmo extendido encuentra
    enteros x, y con a*x + m*y = mcd(a, m). Si mcd = 1, entonces
    a*x ≡ 1 (mod m), es decir, x es el inverso de a.
    """
    r0, r1 = m, a % m      # residuos
    t0, t1 = 0, 1          # coeficientes de a en cada residuo
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ValueError(f"{a} no tiene inverso módulo {m}")
    return t0 % m


def validar_clave(a: int, m: int = M) -> None:
    """Verifica que gcd(a, m) = 1; si no, el mensaje no sería recuperable."""
    if mcd(a, m) != 1:
        raise ValueError(
            f"Clave inválida: gcd({a}, {m}) = {mcd(a, m)} ≠ 1. "
            f"El cifrado no sería invertible."
        )


def _transformar(texto: str, f) -> str:
    """Aplica f(x) a cada letra (x = posición 0-25), respetando el resto."""
    resultado = []
    for c in texto:
        if c.isalpha() and c.upper() in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            base = ord("A") if c.isupper() else ord("a")
            x = ord(c) - base
            resultado.append(chr(f(x) % M + base))
        else:
            resultado.append(c)
    return "".join(resultado)


def cifrar(mensaje: str, a: int, b: int) -> str:
    validar_clave(a)
    return _transformar(mensaje, lambda x: a * x + b)


def descifrar(criptograma: str, a: int, b: in3t) -> str:
    validar_clave(a)
    a_inv = inverso_modular(a, M)
    return _transformar(criptograma, lambda y: a_inv * (y - b))


def main() -> None:
    print("=== Cifrado afín (m = 26) ===")
    opcion = input("¿Cifrar (c) o descifrar (d)? ").strip().lower()
    try:
        a = int(input("Coeficiente multiplicativo a: "))
        b = int(input("Coeficiente de desplazamiento b: "))
        mensaje = input("Mensaje: ")

        if opcion == "c":
            print("Mensaje cifrado:", cifrar(mensaje, a, b))
        elif opcion == "d":
            print(f"(a^-1 mod {M} = {inverso_modular(a, M) if mcd(a, M) == 1 else '—'})")
            print("Mensaje descifrado:", descifrar(mensaje, a, b))
        else:
            print("Opción no válida. Usa 'c' o 'd'.")
    except ValueError as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
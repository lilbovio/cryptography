def factorizar(n):
    if n < 2:
        return [1, n]
    factores = [1]
    divisor = 2
    while divisor * divisor <= n:
        while n % divisor == 0:
            factores.append(divisor)
            n //= divisor
        divisor += 1 if divisor == 2 else 2
    if n > 1:
        factores.append(n)
    return factores


def main():
    try:
        num = int(input("Introduce un número entero: "))
    except ValueError:
        print("Entrada no válida: introduce un número entero.")
        return
    if num < 1:
        print("Introduce un número entero positivo.")
        return
    print(" x ".join(map(str, factorizar(num))))


if __name__ == "__main__":
    main()
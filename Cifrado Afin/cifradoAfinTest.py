"""
Pruebas unitarias para cifrado_afin.py

Ejecutar (desde la misma carpeta que cifrado_afin.py):
    python test_cifrado_afin.py            # salida normal
    python test_cifrado_afin.py -v         # detalle de cada prueba
    python -m unittest test_cifrado_afin   # equivalente
"""

import string
import unittest

from cifradoAfin import (
    M,
    cifrar,
    descifrar,
    inverso_modular,
    mcd,
    validar_clave,
)

# Valores de 'a' con gcd(a, 26) = 1  ->  {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}
CLAVES_A_VALIDAS = [a for a in range(1, M) if mcd(a, M) == 1]
# Valores de 'a' con gcd(a, 26) != 1 (pares y 13)
CLAVES_A_INVALIDAS = [a for a in range(0, M) if mcd(a, M) != 1]


class TestMCD(unittest.TestCase):
    def test_casos_conocidos(self):
        self.assertEqual(mcd(12, 18), 6)
        self.assertEqual(mcd(5, 26), 1)
        self.assertEqual(mcd(13, 26), 13)
        self.assertEqual(mcd(26, 4), 2)

    def test_con_cero(self):
        self.assertEqual(mcd(0, 26), 26)
        self.assertEqual(mcd(7, 0), 7)

    def test_es_conmutativo(self):
        for a in range(1, 40):
            for b in range(1, 40):
                self.assertEqual(mcd(a, b), mcd(b, a))


class TestInversoModular(unittest.TestCase):
    def test_tabla_de_inversos_mod_26(self):
        esperados = {
            1: 1, 3: 9, 5: 21, 7: 15, 9: 3, 11: 19,
            15: 7, 17: 23, 19: 11, 21: 5, 23: 17, 25: 25,
        }
        for a, inv in esperados.items():
            with self.subTest(a=a):
                self.assertEqual(inverso_modular(a, M), inv)

    def test_a_por_inverso_es_1_mod_m(self):
        for a in CLAVES_A_VALIDAS:
            with self.subTest(a=a):
                self.assertEqual((a * inverso_modular(a, M)) % M, 1)

    def test_resultado_en_rango(self):
        for a in CLAVES_A_VALIDAS:
            self.assertTrue(0 <= inverso_modular(a, M) < M)

    def test_otros_modulos(self):
        self.assertEqual(inverso_modular(3, 7), 5)    # 3*5 = 15 = 2*7 + 1
        self.assertEqual(inverso_modular(7, 40), 23)  # 7*23 = 161 = 4*40 + 1
        self.assertEqual(inverso_modular(1, 10), 1)

    def test_a_mayor_que_m_se_reduce(self):
        # 31 ≡ 5 (mod 26), por lo que su inverso también es 21
        self.assertEqual(inverso_modular(31, M), 21)

    def test_sin_inverso_lanza_error(self):
        for a in CLAVES_A_INVALIDAS:
            with self.subTest(a=a):
                with self.assertRaises(ValueError):
                    inverso_modular(a, M)


class TestValidarClave(unittest.TestCase):
    def test_claves_validas_no_lanzan_error(self):
        for a in CLAVES_A_VALIDAS:
            with self.subTest(a=a):
                validar_clave(a)  # no debe lanzar excepción

    def test_claves_invalidas_lanzan_error(self):
        for a in CLAVES_A_INVALIDAS:
            with self.subTest(a=a):
                with self.assertRaises(ValueError):
                    validar_clave(a)

    def test_mensaje_de_error_informativo(self):
        with self.assertRaises(ValueError) as ctx:
            validar_clave(13)
        self.assertIn("gcd(13, 26)", str(ctx.exception))

    def test_cifrar_y_descifrar_validan_la_clave(self):
        with self.assertRaises(ValueError):
            cifrar("hola", 13, 2)
        with self.assertRaises(ValueError):
            descifrar("hola", 2, 2)


class TestCifrar(unittest.TestCase):
    def test_vector_clasico_a5_b8(self):
        # Ejemplo típico de libros de texto
        self.assertEqual(cifrar("AFFINECIPHER", 5, 8), "IHHWVCSWFRCP")

    def test_vector_hola_mundo(self):
        self.assertEqual(
            cifrar("Hola Mundo, criptografia 2026", 5, 8),
            "Rali Qevxa, spwfzampihwi 2026",
        )

    def test_una_letra(self):
        # E(0) = 5*0 + 8 = 8 -> 'I'
        self.assertEqual(cifrar("A", 5, 8), "I")
        # E(25) = 5*25 + 8 = 133 = 5*26 + 3 -> 'D'
        self.assertEqual(cifrar("Z", 5, 8), "D")

    def test_identidad_a1_b0(self):
        self.assertEqual(cifrar("Mensaje Secreto", 1, 0), "Mensaje Secreto")

    def test_atbash_a25_b25(self):
        # a = m-1, b = m-1  ->  A<->Z, B<->Y, ...
        self.assertEqual(cifrar("ABC", 25, 25), "ZYX")
        self.assertEqual(cifrar("abcxyz", 25, 25), "zyxcba")

    def test_b_mayor_que_m_se_reduce(self):
        self.assertEqual(cifrar("HOLA", 5, 8), cifrar("HOLA", 5, 8 + M))
        self.assertEqual(cifrar("HOLA", 5, 8), cifrar("HOLA", 5, 8 + 5 * M))

    def test_b_negativo(self):
        self.assertEqual(cifrar("HOLA", 5, -3), cifrar("HOLA", 5, M - 3))

    def test_a_mayor_que_m_se_reduce(self):
        self.assertEqual(cifrar("HOLA", 5, 8), cifrar("HOLA", 5 + M, 8))

    def test_conserva_mayusculas_y_minusculas(self):
        resultado = cifrar("HoLa", 5, 8)
        self.assertTrue(resultado[0].isupper())
        self.assertTrue(resultado[1].islower())
        self.assertTrue(resultado[2].isupper())
        self.assertTrue(resultado[3].islower())

    def test_no_altera_caracteres_que_no_son_letras(self):
        texto = "  123, ¡hola!  \n\t-_.  "
        resultado = cifrar(texto, 7, 3)
        for original, cifrado in zip(texto, resultado):
            if not original.isalpha():
                self.assertEqual(original, cifrado)

    def test_cadena_vacia(self):
        self.assertEqual(cifrar("", 5, 8), "")

    def test_solo_simbolos(self):
        self.assertEqual(cifrar("1234 !?", 5, 8), "1234 !?")

    def test_misma_longitud(self):
        texto = "Texto de prueba, con 3 números."
        self.assertEqual(len(cifrar(texto, 9, 4)), len(texto))

    def test_letras_con_acento_y_enie_no_se_modifican(self):
        # El alfabeto es A-Z (m = 26): Ñ y vocales acentuadas quedan igual
        self.assertEqual(cifrar("ñáéíóú", 5, 8), "ñáéíóú")


class TestDescifrar(unittest.TestCase):
    def test_vector_clasico_a5_b8(self):
        self.assertEqual(descifrar("IHHWVCSWFRCP", 5, 8), "AFFINECIPHER")

    def test_vector_hola_mundo(self):
        self.assertEqual(
            descifrar("Rali Qevxa, spwfzampihwi 2026", 5, 8),
            "Hola Mundo, criptografia 2026",
        )

    def test_una_letra(self):
        self.assertEqual(descifrar("I", 5, 8), "A")
        self.assertEqual(descifrar("D", 5, 8), "Z")

    def test_atbash_es_su_propia_inversa(self):
        self.assertEqual(descifrar("ZYX", 25, 25), "ABC")

    def test_conserva_formato(self):
        self.assertEqual(descifrar("Rali Qevxa!", 5, 8), "Hola Mundo!")

    def test_cadena_vacia(self):
        self.assertEqual(descifrar("", 5, 8), "")


class TestIdaYVuelta(unittest.TestCase):
    """descifrar(cifrar(x)) == x para cualquier clave válida."""

    def test_todas_las_claves_validas(self):
        texto = string.ascii_letters + " 0123456789,.;:!?"
        for a in CLAVES_A_VALIDAS:
            for b in range(M):
                with self.subTest(a=a, b=b):
                    self.assertEqual(descifrar(cifrar(texto, a, b), a, b), texto)

    def test_texto_largo(self):
        texto = "El veloz murciélago hindú comía feliz cardillo y kiwi. " * 50
        self.assertEqual(descifrar(cifrar(texto, 17, 11), 17, 11), texto)

    def test_cifrar_cambia_el_texto_salvo_clave_identidad(self):
        texto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for a in CLAVES_A_VALIDAS:
            for b in range(M):
                if (a, b) == (1, 0):
                    continue
                with self.subTest(a=a, b=b):
                    self.assertNotEqual(cifrar(texto, a, b), texto)

    def test_cifrado_es_biyectivo(self):
        # Cada letra del alfabeto se mapea a una letra distinta (permutación)
        alfabeto = string.ascii_uppercase
        for a in CLAVES_A_VALIDAS:
            with self.subTest(a=a):
                self.assertEqual(sorted(cifrar(alfabeto, a, 7)), list(alfabeto))


class TestCasoCesar(unittest.TestCase):
    """César es el caso particular a = 1 del cifrado afín."""

    @staticmethod
    def cesar(texto, k):
        """Implementación independiente de César para comparar."""
        salida = []
        for c in texto:
            if c.isascii() and c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                salida.append(chr((ord(c) - base + k) % 26 + base))
            else:
                salida.append(c)
        return "".join(salida)

    def test_afin_con_a1_equivale_a_cesar(self):
        texto = "Ataque al amanecer, 2026!"
        for k in range(M):
            with self.subTest(k=k):
                self.assertEqual(cifrar(texto, 1, k), self.cesar(texto, k))

    def test_cesar_clasico_desplazamiento_3(self):
        self.assertEqual(cifrar("ATAQUE", 1, 3), "DWDTXH")

    def test_descifrado_con_a1_es_traslacion_inversa(self):
        self.assertEqual(descifrar("DWDTXH", 1, 3), "ATAQUE")

    def test_inverso_de_1_es_1(self):
        self.assertEqual(inverso_modular(1, M), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
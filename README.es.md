# cortex9-openssl-asn1-string-nul-scanner

**Heurística de advertencias**, léxica e intraprocedural, para usos de
bytes de `ASN1_STRING` que asumen terminación NUL. Es la clase de
CVE-2021-3712. No compila ni ejecuta nada, y **no prueba seguridad ni
inseguridad**.

Etiquetas:

- **`NUL_SINK_WARNING`:** el patrón llega a `%s` sin precisión o a una
  función que busca NUL. Es una advertencia, no una prueba de lectura
  real.
- **`BOUNDED_PATTERN`:** el uso encaja en un patrón cuya cota está ligada
  sintácticamente al mismo objeto origen. No implica seguridad: supone
  `length >= 0` y que nada cambia entre la cota y el uso.
- **`UNKNOWN`:** las reglas no pueden relacionar el uso con una cota. Es el
  valor por defecto honesto.
- **`NO_SOURCE`:** no se reconoció ninguna fuente ASN1.

Resultados:

- **Corpus upstream** (ajustado y no independiente): 10 advertencias en
  las funciones etiquetadas como inseguras antes del fix, y 4 `UNKNOWN`
  en funciones corregidas. Que no haya advertencias después del fix
  **no** demuestra la ausencia de falsos positivos.
- **Corpus sintético:** 31 de 31 casos dan la etiqueta esperada,
  incluidas 10 sondas de falsos seguros, ninguna marcada como
  `BOUNDED_PATTERN`.

Licencia: Apache-2.0. Los archivos `fixtures/upstream/*.c` son fuentes de
OpenSSL sin modificar, bajo la licencia OpenSSL/SSLeay.

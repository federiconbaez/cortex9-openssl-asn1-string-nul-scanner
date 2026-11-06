# cortex9-openssl-asn1-string-nul-scanner

Escáner léxico e intraprocedural de usos de bytes de `ASN1_STRING` que
asumen terminación NUL. Es la clase de CVE-2021-3712 (aviso de OpenSSL del
24-08-2021, corregido en 1.1.1l).

**No es grep ni un compilador.** Funciona así:

- tokeniza el C y separa sentencias;
- sigue fuentes (`->data`, `ASN1_STRING_get0_data`, `X509_alias_get0`…) y
  variables derivadas, así como expresiones de longitud;
- clasifica cada uso como `UNSAFE`, `SAFE` o `UNKNOWN`.

No compila ni ejecuta nada.

Resultados:

- **Corpus upstream** (13 funciones × antes/después, etiquetadas a mano
  desde los diffs): detecta 10 de 10 funciones inseguras antes del fix,
  con 0 falsos positivos después. En 3 funciones corregidas responde
  `UNKNOWN`, porque son guardas que las reglas léxicas no siguen.
- **Corpus sintético:** 21 casos, 21 coincidencias con la especificación,
  incluidas 4 limitaciones documentadas.

Las reglas se ajustaron después de ver el corpus upstream, así que esas
cifras **no** son una evaluación independiente.

Licencia: Apache-2.0. Los archivos `fixtures/upstream/*.c` son fuentes de
OpenSSL sin modificar, bajo la licencia OpenSSL/SSLeay.

# Guía práctica / Practice guide

Ejercicios **offline** de lectura de C. El escáner solo lee texto: no
compila ni ejecuta nada. *English summary at the end.*

## Comandos locales

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m asn1nul corpus
python3 scripts/gen_results.py /tmp/out && diff -r results /tmp/out
```

## Ejercicios graduados

**Nivel 1: la clase de bug.** Lee el aviso del 24-08-2021. ¿Por qué
`%s` sobre `->data` puede leer de más?
Comprobación: `scan fixtures/synthetic/s01_printf_s.c` devuelve `UNSAFE`
con la regla `%s without precision`.

**Nivel 2: el fix de printf.** Compara s01 con s02.
Comprobación: s02 da `SAFE` (`%.*s with length`).

**Nivel 3: precisión literal.** ¿Por qué `%.8s` no es necesariamente
seguro?
Comprobación: s03 da `UNKNOWN`; su `truth` es `UNSAFE`, y el caso está
marcado como limitación.

**Nivel 4: alias.** Escanea `X509_aux_print` antes y después de
d9d838ddc0ed.
Comprobación: `c5b2c075feea…` → `UNSAFE` y `d9d838ddc0ed…` → `SAFE` en
`results/upstream.csv`.

**Nivel 5: propagación.** Explica cómo s11 llega a un sumidero.
Comprobación: `h` queda contaminado al asignarle `u->data`, y
`strchr(h, …)` es un sumidero NUL → `UNSAFE`.

**Nivel 6: v3_ncons.** ¿Qué tres funciones corregidas quedan en `UNKNOWN`
y por qué?
Comprobación: `i2v_GENERAL_NAME`, `nc_dns` y `nc_email`
(`unknown_on_safe` = 3), por guardas en sentencias previas o límites con
diferencias de punteros.

**Nivel 7: falsos positivos y negativos.** Ejecuta s20 y s21.
Comprobación: s20 da `UNSAFE` aunque no sea ASN1 (`overclaims_unsafe`), y
s21 da `NO_SOURCE` porque la macro no se expande (`missed`).

**Nivel 8: honestidad de métricas.** ¿Por qué el 10/10 upstream no es una
evaluación independiente?
Comprobación: LIMITATIONS.md documenta que las reglas se ajustaron tras
ver el corpus; en `summary.csv` no hay ninguna fila `false_positive`.

## English summary

Eight levels: the bug class from the advisory, the `%.*s` fix, literal
precision, the alias case, taint propagation, the three fixed functions
the lexical rules cannot prove safe, the documented false positive and
false negative, and why the upstream numbers are not a held-out
evaluation.

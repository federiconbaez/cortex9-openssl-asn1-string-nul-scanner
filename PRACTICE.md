# Guía práctica / Practice guide

Ejercicios **offline** de lectura de C con una heurística de
advertencias. No se compila ni se ejecuta nada. Ninguna etiqueta es una
prueba de seguridad. *English summary at the end.*

## Comandos locales

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m asn1nul corpus
python3 scripts/gen_results.py /tmp/out && diff -r results /tmp/out
```

## Ejercicios graduados

**Nivel 1: la clase de bug.** Lee el aviso del 24-08-2021 y escanea
`fixtures/synthetic/s01_printf_s.c`.
Comprobación: `NUL_SINK_WARNING`, con la regla `%s without precision`.
Es una advertencia, no una lectura demostrada.

**Nivel 2: patrón acotado.** Compara s01 con s02.
Comprobación: s02 da `BOUNDED_PATTERN`. Explica por qué eso no significa
"seguro" (supone `length >= 0`).

**Nivel 3: longitud mayor al buffer.** Escanea s22 (`e->length + 8`).
Comprobación: `UNKNOWN`; la aritmética sobre la longitud no se acepta.

**Nivel 4: precisión negativa.** Escanea s23 (`%.*s` con -1). ¿Qué hace
printf con una precisión negativa?
Comprobación: la ignora, así que se comporta como `%s`. El escáner da
`UNKNOWN`, no `BOUNDED_PATTERN`.

**Nivel 5: off-by-one.** Escanea s24 (`i <= s->length`) y s25 (`p[n]`).
Comprobación: ambos dan `UNKNOWN`; solo se acepta `<` dentro del cuerpo
del `for`.

**Nivel 6: nombres engañosos.** Escanea s26 (`unrelated_len`) y s27
(`t->length` para `s->data`).
Comprobación: ambos dan `UNKNOWN`, porque la cota debe tener el mismo
origen.

**Nivel 7: guardas que no dominan.** Escanea s28, s29 y s30.
Comprobación: los tres dan `UNKNOWN` (guarda en una sentencia previa,
`||`, e índice usado después del bucle).

**Nivel 8: honestidad de métricas.** En `results/summary.csv`, ¿qué falta
para afirmar que no hay falsos positivos?
Comprobación: el corpus upstream fue ajustado y no es independiente, y
s20 es un falso positivo conocido. "0 advertencias después del fix" no es
una métrica de falsos positivos.

## English summary

Eight levels: the warning label, why `BOUNDED_PATTERN` is not "safe",
and the heuristic false-safe probes (length + k, a negative precision,
`<=` and `p[len]`, unrelated or foreign lengths, non-dominating guards).
The last level explains why the tuned upstream counts are not a
false-positive rate.

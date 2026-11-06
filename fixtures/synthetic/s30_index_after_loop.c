int f(ASN1_STRING *s) { int i, acc = 0; const unsigned char *p = s->data; for (i = 0; i < s->length; i++) { acc += p[i]; } return acc + p[i]; }

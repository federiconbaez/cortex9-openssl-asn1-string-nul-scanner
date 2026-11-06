int f(ASN1_STRING *s) { int i, x = 0; const unsigned char *p = s->data; for (i = 0; i <= s->length; i++) x ^= p[i]; return x; }

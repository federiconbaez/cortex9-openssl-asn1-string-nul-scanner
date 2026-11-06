void f(BIO *out, ASN1_STRING *s) { int i, n = s->length; const unsigned char *p = s->data; for (i = 0; i < n; i++) BIO_printf(out, "%02x", p[i]); }

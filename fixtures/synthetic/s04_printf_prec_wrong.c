void f(BIO *out, ASN1_STRING *s, int k) { BIO_printf(out, "%.*s\n", k, s->data); }

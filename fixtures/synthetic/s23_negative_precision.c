void f(BIO *out, ASN1_STRING *s) { BIO_printf(out, "%.*s\n", -1, s->data); }

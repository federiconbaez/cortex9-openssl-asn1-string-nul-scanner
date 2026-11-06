void f(BIO *out, ASN1_STRING *s) { BIO_printf(out, "%.8s\n", s->data); }

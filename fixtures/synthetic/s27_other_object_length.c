void f(BIO *out, ASN1_STRING *s, ASN1_STRING *t) { BIO_printf(out, "%.*s", t->length, s->data); }

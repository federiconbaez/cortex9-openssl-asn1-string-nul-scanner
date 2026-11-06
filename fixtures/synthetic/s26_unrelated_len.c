void f(BIO *out, ASN1_STRING *s, int unrelated_len) { BIO_printf(out, "%.*s", unrelated_len, s->data); }

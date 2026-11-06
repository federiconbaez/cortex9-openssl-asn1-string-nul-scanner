#define SHOW(o, s) BIO_printf(o, "%s", (s)->data)
void f(BIO *out, ASN1_STRING *s) { SHOW(out, s); }

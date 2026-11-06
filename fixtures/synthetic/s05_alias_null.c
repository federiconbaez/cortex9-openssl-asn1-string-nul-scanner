void f(BIO *out, X509 *x) { unsigned char *a = X509_alias_get0(x, NULL); if (a) BIO_printf(out, "%s", a); }

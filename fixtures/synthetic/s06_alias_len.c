void f(BIO *out, X509 *x) { int n; unsigned char *a = X509_alias_get0(x, &n); if (a) BIO_printf(out, "%.*s", n, a); }

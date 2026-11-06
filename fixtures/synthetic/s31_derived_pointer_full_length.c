char *f(ASN1_STRING *s) { const char *q = (const char *)s->data + 1; return OPENSSL_strndup(q, s->length); }

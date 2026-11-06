char *f(ASN1_IA5STRING *e) { return OPENSSL_strndup((char *)e->data, e->length); }

int f(ASN1_IA5STRING *u) { return memchr(u->data, 0, u->length) != NULL; }

int f(ASN1_IA5STRING *u, size_t k) { return memchr(u->data, 0, k) != NULL; }

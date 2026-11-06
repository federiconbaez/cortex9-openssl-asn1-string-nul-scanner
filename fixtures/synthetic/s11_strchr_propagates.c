int f(ASN1_IA5STRING *u) { const char *h = (char *)u->data; const char *c = strchr(h, 58); return c != NULL; }

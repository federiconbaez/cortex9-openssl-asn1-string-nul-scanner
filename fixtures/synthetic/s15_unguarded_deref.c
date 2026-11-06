int f(ASN1_IA5STRING *b) { const char *p = (char *)b->data; if (*p == 46) return 1; return 0; }

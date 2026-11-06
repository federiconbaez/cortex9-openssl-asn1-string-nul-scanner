int f(ASN1_IA5STRING *b) { int x = 0; const char *p = (char *)b->data; if (b->length > 0) x = 1; if (*p == 46) return 1; return x; }

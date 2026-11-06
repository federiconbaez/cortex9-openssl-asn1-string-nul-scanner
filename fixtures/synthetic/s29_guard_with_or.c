int f(ASN1_IA5STRING *b) { const char *p = (char *)b->data; if (b->length > 0 || *p == 46) return 1; return 0; }

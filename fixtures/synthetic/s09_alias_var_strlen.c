size_t f(ASN1_STRING *s) { const char *p = (const char *)ASN1_STRING_get0_data(s); return strlen(p); }

size_t f(ASN1_STRING *s) { const char *p = (const char *)s->data; p = "fixed"; return strlen(p); }

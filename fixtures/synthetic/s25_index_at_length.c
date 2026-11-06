int f(ASN1_STRING *s) { int n = s->length; const unsigned char *p = s->data; return p[n]; }

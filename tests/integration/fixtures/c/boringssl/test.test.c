// TEST-RULE: c.crypto.boringssl.detect-usage

#ifdef OPENSSL_IS_BORINGSSL
void f(void) {}
#endif

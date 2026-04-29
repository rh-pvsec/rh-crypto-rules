// TEST-RULE: c.crypto.boringssl.detect-usage
// TEST-METADATA: library=BoringSSL, assetType=algorithm

#ifdef OPENSSL_IS_BORINGSSL
void f(void) {}
#endif

// TEST-RULE: c.crypto.libressl.detect-import
// TEST-METADATA: library=LibreSSL

#include <openssl/opensslv.h>

#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3040000fL
#endif

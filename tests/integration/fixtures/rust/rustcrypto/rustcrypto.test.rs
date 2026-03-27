// TEST-RULE: rust.crypto.rustcrypto.ml-kem
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=kem, algorithmFamily=ML-KEM, algorithmName=ML-KEM, library=RustCrypto

use ml_kem::ExpandedKeyEncoding;

// TEST-RULE: rust.crypto.rustcrypto.rsa
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSAES-PKCS1, algorithmName=RSA-PKCS1-v1.5, library=RustCrypto

rsa::pkcs1v15::SigningKey

// TEST-RULE: rust.crypto.rustcrypto.pkcs1
// TEST-METADATA: assetType=related-crypto-material, library=RustCrypto

use pkcs1::{RsaOaepParams, RsaPssParams, TrailerField};

// TEST-RULE: rust.crypto.rustcrypto.pkcs5
// TEST-METADATA: assetType=related-crypto-material, library=RustCrypto

let scheme = pkcs5::EncryptionScheme::try_from(PBES2_PBKDF2_SHA256_DESEDE3CBC_ALG_ID).unwrap();

// TEST-RULE: rust.crypto.rustcrypto.pkcs8
// TEST-METADATA: assetType=related-crypto-material, library=RustCrypto

let enc_pk =
        pkcs8::EncryptedPrivateKeyInfoOwned::try_from(ED25519_DER_AES256_GCM_SCRYPT_EXAMPLE).unwrap();

// TEST-RULE: rust.crypto.rustcrypto.x509-cert
// TEST-METADATA: assetType=certificate, library=RustCrypto

use x509_cert::*;

// TEST-RULE: rust.crypto.rustcrypto.dsa
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=DSA, algorithmName=DSA, library=RustCrypto

use dsa::Components

// TEST-RULE: rust.crypto.rustcrypto.ecdsa
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, algorithmName=ECDSA, library=RustCrypto

type SignatureBytes = ecdsa::SignatureBytes<MockCurve>

// TEST-RULE: rust.crypto.rustcrypto.ed25519
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=EdDSA, algorithmName=Ed25519, library=RustCrypto

use ed25519::Signature;

// TEST-RULE: rust.crypto.rustcrypto.blake2
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=BLAKE2, algorithmName=BLAKE2, library=RustCrypto

use blake2::{Blake2b512, Blake2s256, Digest};

// TEST-RULE: rust.crypto.rustcrypto.sha2
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-2, algorithmName=SHA-256, library=RustCrypto

use sha2::{Sha256, Digest};

// TEST-RULE: rust.crypto.rustcrypto.sha3
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-3, algorithmName=SHA3-256, library=RustCrypto

use sha3::{Digest, Sha3_256}

// TEST-RULE: rust.crypto.rustcrypto.hmac
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC, library=RustCrypto

use hmac::{Hmac, KeyInit, Mac};

// TEST-RULE: rust.crypto.rustcrypto.argon2
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=kdf, algorithmFamily=Argon2, algorithmName=Argon2, library=RustCrypto

use argon2::Algorithm

// TEST-RULE: rust.crypto.rustcrypto.pbkdf2
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=kdf, algorithmFamily=PBKDF2, algorithmName=PBKDF2, library=RustCrypto

use pbkdf2::{Params, Pbkdf2, password_hash::PasswordHasher, phc::PasswordHash};

// TEST-RULE: rust.crypto.rustcrypto.scrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=kdf, algorithmFamily=scrypt, algorithmName=scrypt, library=RustCrypto

use scrypt::{Params, scrypt};

// TEST-RULE: rust.crypto.rustcrypto.aes-gcm
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=AES, algorithmName=AES-GCM, library=RustCrypto

use aes_gcm::Aes128Gcm;

// TEST-RULE: rust.crypto.rustcrypto.aes-gcm-siv
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=AES, algorithmName=AES-GCM-SIV, library=RustCrypto

use aes_gcm_siv::aead::{Aead, KeyInit, Payload, array::Array};

// TEST-RULE: rust.crypto.rustcrypto.chacha20poly1305
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=ChaCha20, algorithmName=ChaCha20-Poly1305, library=RustCrypto

use chacha20poly1305::ChaCha20Poly1305;

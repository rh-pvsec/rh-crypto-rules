// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-bignp256
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-256, library=RustCrypto

use bignp256::ecdsa

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-bp256
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-256, library=RustCrypto

use bp256::r1::{ProjectivePoint, Scalar};

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-bp384
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-384, library=RustCrypto

use bp384::BrainpoolP384r1;

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-ed448-goldilocks
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=ED448, library=RustCrypto

use ed448_goldilocks::{
    Decaf448, DecafPoint, DecafScalar, Ed448, EdwardsPoint, EdwardsScalar, MontgomeryPoint,
    elliptic_curve::{Generate, group::GroupEncoding},
};

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-hash2curve
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=hash2curve, library=RustCrypto

use hash2curve::ExpandMsgXmd;

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-k256
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=K-256, library=RustCrypto

k256::NonZeroScalar::new()

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-p192
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-192, library=RustCrypto

use p192::{
    AffinePoint, ProjectivePoint, Scalar,
    test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
};

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-p224
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-224, library=RustCrypto

use p224::AffinePoint;

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-p256
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-256, library=RustCrypto

use p256::elliptic_curve::pkcs8::{EncodePrivateKey, EncodePublicKey}

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-p384
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-384, library=RustCrypto

let pubkey = p384::Sec1Point::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-p521
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=P-521, library=RustCrypto

use p521::Scalar;

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-primefield
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=primefield, library=RustCrypto

use primefield::FieldElement;

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-primeorder
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=primeorder, library=RustCrypto

use primeorder::PrimeCurveParams;

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-sm2
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=sm2, library=RustCrypto

let secret_key = sm2::SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();

// TEST-RULE: rust.crypto.rustcrypto.elliptic-curves-x448
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=elliptic-curves, algorithmName=x448, library=RustCrypto

use x448::PublicKey;


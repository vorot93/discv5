//! Implements the static ecdh algorithm required by discv5 in terms of the `k256` library.
use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};

pub fn ecdh(public_key: &VerifyingKey, secret_key: &SigningKey) -> Vec<u8> {
    (*PublicKey::from_sec1_bytes(public_key.to_bytes().as_ref())
        .unwrap()
        .as_affine()
        * *SecretKey::from_bytes(secret_key.to_bytes())
            .unwrap()
            .secret_scalar())
    .to_encoded_point(true)
    .as_bytes()
    .to_vec()
}

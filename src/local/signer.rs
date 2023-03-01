use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

// Struct defines how a signer
pub struct Signer {
    // Participant's index
    pub index: u32,
    // Participant's public key
    pub pubkeys: Vec<PublicKey>,
    // Participant's private key
    share: Scalar,
}

pub struct PublicKey {
    pub index: u32,
    pub pubkey: RistrettoPoint,
}

impl PublicKey {}

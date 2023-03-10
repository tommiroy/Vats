use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use super::header::Committee;

pub fn musig_coef(committee: Committee, big_y: RistrettoPoint) -> Scalar {
    let mut hasher = Sha512::new();
    // Go through every participant in the committee.
    // Get the public key and add it to the hash
    for participant in committee.signers {
        hasher.update(participant.public_key.key.compress().as_bytes());
    }
    // Add participant own public key
    hasher.update(big_y.compress().as_bytes());

    // Convert from hash in bytes to Scalar value
    let mut hash_in_bytes = [0u8; 64];
    hash_in_bytes.copy_from_slice(hasher.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&hash_in_bytes)
}

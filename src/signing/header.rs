use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

#[derive(Clone)]
pub struct PrivateKey {
    // ID of private key
    pub id: u32,
    // The actually private key
    key: Scalar,
}
impl PrivateKey {
    pub fn get_key(&self) -> Scalar {
        self.key
    }

    pub fn new(id: u32, key: Scalar) -> PrivateKey {
        PrivateKey { id, key }
    }
}

#[derive(Clone)]
pub struct PublicKey {
    // ID of private key
    pub id: u32,
    // The actually public key
    pub key: RistrettoPoint,
}
impl PublicKey {
    pub fn new(id: u32, key: RistrettoPoint) -> PublicKey {
        PublicKey { id, key }
    }
}

// Committee struct to hold all participants in the committee
#[derive(Clone)]
pub struct Committee {
    // List of all participants in the committee
    pub signers: Vec<Signer>,
    // The committee's public key: Y tilde
    pub public_key: RistrettoPoint,
}

impl Committee {
    pub fn new(signers: Vec<Signer>) -> Committee {
        Committee {
            signers,
            public_key: RistrettoPoint::default(),
        }
    }
}

// Participant struct to hold possible signers of the message
// Each participant has a private key and a public key associated with it
#[derive(Clone)]
pub struct Signer {
    pub id: u32,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

impl Signer {
    pub fn new(id: u32, private_key: PrivateKey, public_key: PublicKey) -> Signer {
        Signer {
            id,
            private_key,
            public_key,
        }
    }
}

// #################### Hash Coefficient ###########################
pub fn musig_coef(com: Committee, big_y: RistrettoPoint) -> Scalar {
    let mut hasher = Sha512::new();
    // Go through every participant in the committee.
    // Get the public key and add it to the hash
    for participant in com.signers {
        hasher.update(participant.public_key.key.compress().as_bytes());
    }
    // Add participant own public key
    hasher.update(big_y.compress().as_bytes());

    // Convert from hash in bytes to Scalar value
    let mut hash_in_bytes = [0u8; 64];
    hash_in_bytes.copy_from_slice(hasher.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&hash_in_bytes)
}

// #################### Hash Signature ###########################
pub fn hash_sig(tilde_y: RistrettoPoint, big_r: RistrettoPoint, m: String) -> Scalar {
    // Hashes the signature on the message
    let mut hasher = Sha512::new();

    // challange :=H_{sig}(\widetilde{Y},R,m)
    // hashing the for the signature challenge

    hasher.update(tilde_y.compress().as_bytes());
    hasher.update(big_r.compress().as_bytes());
    hasher.update(m.as_bytes());

    // convert the hash to a scalar to get the correct calulations
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);

    Scalar::from_bytes_mod_order_wide(&result_bytes)
}
// #################### Hash Nonce ###########################

pub fn hash_non(com: Committee, outs: Vec<RistrettoPoint>, m: String) -> Scalar {
    let mut hasher = Sha512::new();
    // hash $b:= H_{non}(\widetilde{Y},(R_1,...,R_v),m)$

    hasher.update(com.public_key.compress().as_bytes());

    for out in outs.iter() {
        hasher.update(out.compress().as_bytes());
    }

    hasher.update(m.as_bytes());

    // convert the hash to a scalar to get the correct calulations
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);

    Scalar::from_bytes_mod_order_wide(&result_bytes)
}

// #################### Helper functions ###########################

// Compute larange coefficient
// Used in key aggregation and signing
pub fn compute_lagrange_coefficient(committee: Committee, x0: u32) -> Scalar {
    let mut lagrange_coefficient = Scalar::one();

    // Standard lagrange coefficient calculation
    // https://en.wikipedia.org/wiki/Lagrange_polynomial
    for x1 in committee.signers.iter() {
        if x1.id != x0 {
            let calc = Scalar::from(x1.id) * (Scalar::from(x1.id) - Scalar::from(x0)).invert();
            lagrange_coefficient *= calc;
        }
    }
    lagrange_coefficient
}

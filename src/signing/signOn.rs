use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::signing::keyAgg::keyAgg;
use crate::signing::muSigCoef::muSigCoef;
use sha2::{Digest, Sha512};

pub fn SignOn(
    state1: Vec<Scalar>,
    out: Vec<RistrettoPoint>,
    m: String,
    sk: (u32, Scalar),
    pk: RistrettoPoint,
    L: Vec<RistrettoPoint>,
    lagrange_coeff: Scalar,
    participants: Vec<u32>,
) -> (RistrettoPoint, Scalar, RistrettoPoint) {
    let rho_i = muSigCoef(L.clone(), pk);
    let tilde_y = keyAgg(L, participants);
    // hash b_pre with sha512
    let b = hash_non(tilde_y, out.clone(), m.clone());

    // prod = out[j]^(b^(j-1))
    let mut big_r = RistrettoPoint::identity();
    for (j, _) in out.iter().enumerate() {
        let bpowj = scalar_pow(b, j as u32);
        // make bpowj a scalar

        big_r += out[j] * bpowj;
    }

    // compute challenge
    let c = hash_sig(tilde_y, big_r, m);

    println!("HASHING SIGNATURE ON HASHON! {:?}", c);
    // make z_1

    let mut rhf = Scalar::zero();
    for (j, _) in out.iter().enumerate() {
        let bpowj = scalar_pow(b, j as u32);
        // make bpowj a scalar
        let temp = state1[j] * bpowj;
        // make rhf to Scaler
        rhf += temp;
    }
    // calculate z_1
    let z_1 = sk.1 * lagrange_coeff * rho_i * c + rhf;

    (big_r, z_1, tilde_y)
}

// Helpers
//
//
//
// For hashing the message with sha512 and returning a Scalar hashing PK, (R,..R), m

pub fn hash_sig(tilde_y: RistrettoPoint, r: RistrettoPoint, m: String) -> Scalar {
    let mut hasher = Sha512::new();
    // hash b_pre
    hasher.update(tilde_y.compress().as_bytes());
    hasher.update(r.compress().as_bytes());
    hasher.update(m.as_bytes());
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);
    Scalar::from_bytes_mod_order_wide(&result_bytes)
}

pub fn hash_non(tilde_y: RistrettoPoint, out: Vec<RistrettoPoint>, m: String) -> Scalar {
    let mut hasher = Sha512::new();
    // hash b_pre
    hasher.update(tilde_y.compress().as_bytes());
    for i in 0..out.len() {
        hasher.update(out[i].compress().as_bytes());
    }
    hasher.update(m.as_bytes());
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);
    Scalar::from_bytes_mod_order_wide(&result_bytes)
}

fn scalar_pow(base: Scalar, exp: u32) -> Scalar {
    let mut result = Scalar::one();
    for _ in 0..exp {
        result *= base;
    }
    result
}

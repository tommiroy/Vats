use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::dealer::keyAgg::keyAgg;
use crate::dealer::muSigCoef::muSigCoef;
use sha2::{Digest, Sha512};

pub fn SignOn(
    state1: Vec<Scalar>,
    out: Vec<RistrettoPoint>,
    m: String,
    sk: (u32, Scalar),
    pk: RistrettoPoint,
    L: Vec<RistrettoPoint>,
    lagrange_coeff: Scalar,
) -> (RistrettoPoint, Scalar) {
    let rho_i = muSigCoef(L.clone(), pk);
    let tilde_y = keyAgg(L);
    // hash b_pre with sha512
    let b = hash_non(tilde_y, out.clone(), m.clone());

    // prod = out[j]^(b^(j-1))
    let mut prod = RistrettoPoint::identity();
    for j in 0..out.len() {
        let bpowj = b * Scalar::from((j) as u32);
        // make bpowj a scalar
        let bpowj = Scalar::from_bytes_mod_order(*bpowj.compress().as_bytes());
        prod += out[j] * bpowj;
    }

    // compute challenge
    let c = hash_sig(tilde_y, prod, m);

    // make z_1

    let mut rhf = RistrettoPoint::identity();
    for j in 0..out.len() {
        let bpowj = b * Scalar::from((j) as u32);
        // make bpowj a scalar
        rhf += state1[j] * bpowj;
    }
    // make rhf a scalar
    let rhf = Scalar::from_bytes_mod_order(*rhf.compress().as_bytes());
    // calculate z_1
    let z_1 = sk.1 * c * rho_i * lagrange_coeff + rhf;

    (prod, z_1)
}

// Helpers
//
//
//
// For hashing the message with sha512 and returning a Scalar hashing PK, (R,..R), m

fn hash_sig(tilde_y: Scalar, r: RistrettoPoint, m: String) -> Scalar {
    let mut hasher = Sha512::new();
    // hash b_pre
    hasher.update(tilde_y.as_bytes());
    hasher.update(r.compress().as_bytes());
    hasher.update(m.as_bytes());
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);
    Scalar::from_bytes_mod_order_wide(&result_bytes)
}

fn hash_non(tilde_y: Scalar, out: Vec<RistrettoPoint>, m: String) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    // hash b_pre
    hasher.update(tilde_y.as_bytes());
    for i in 0..out.len() {
        hasher.update(out[i].compress().as_bytes());
    }
    hasher.update(m.as_bytes());
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);
    //Scalar::from_bytes_mod_order_wide(&result_bytes)
    RistrettoPoint::from_uniform_bytes(&result_bytes)
}

pub fn compute_lagrange_coefficient(shares: Vec<u32>, i: usize) -> Scalar {
    let x_i = Scalar::from(shares[i] as u64);
    let mut lagrange_coefficient = Scalar::one();

    for (j, x_j) in shares.iter().enumerate() {
        if i == j {
            continue;
        }
        let x_j = Scalar::from(*x_j as u64);
        let inv = x_j - x_i;
        lagrange_coefficient *= inv.invert();
    }

    lagrange_coefficient
}

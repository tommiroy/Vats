use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
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
) -> (RistrettoPoint, Scalar, RistrettoPoint) {
    let rho_i = muSigCoef(L.clone(), pk);
    let tilde_y = keyAgg(L);
    // hash b_pre with sha512
    let b = hash_non(tilde_y, out.clone(), m.clone());

    // prod = out[j]^(b^(j-1))
    let mut big_r = RistrettoPoint::identity();
    for j in 0..out.len() {
        let bpowj = b * Scalar::from((j) as u32);
        // make bpowj a scalar
        let bpowj = Scalar::from_bytes_mod_order(*bpowj.compress().as_bytes());
        big_r += out[j] * bpowj;
    }

    // compute challenge
    let c = hash_sig(tilde_y, big_r, m.clone());

    println!("HASHING SIGNATURE ON HASHON! {:?}", c);
    // make z_1

    let mut rhf = Scalar::zero();
    for j in 0..out.len() {
        let bpowj = b * Scalar::from((j) as u32);
        // make bpowj a scalar
        let temp = state1[j] * bpowj;
        // make rhf to Scaler
        rhf += Scalar::from_bytes_mod_order(*temp.compress().as_bytes());
    }
    // calculate z_1
    assert_eq!(&RISTRETTO_BASEPOINT_TABLE * &rhf, big_r);
    let z_1 = c * rho_i * (sk.1 * lagrange_coeff) + rhf;

    //let z_1 = sk.1 * lagrange_coeff;

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

pub fn hash_non(tilde_y: RistrettoPoint, out: Vec<RistrettoPoint>, m: String) -> RistrettoPoint {
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
    //Scalar::from_bytes_mod_order_wide(&result_bytes)
    RistrettoPoint::from_uniform_bytes(&result_bytes)
}

pub fn compute_lagrange_coefficient(shares: Vec<(u32, Scalar)>, x0: u32) -> Scalar {
    let mut li = Scalar::one();
    for (x1, _) in shares.iter() {
        if *x1 != x0 {
            let lui = Scalar::from(*x1) * (Scalar::from(*x1) - Scalar::from(x0)).invert();
            li *= lui;
        }
    }

    li
}

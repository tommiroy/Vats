use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use super::header::*;

use crate::signing::keyAgg::key_agg;
use crate::signing::muSigCoef::musig_coef;

pub fn sign_on(
    signer: Signer,
    state1: Vec<Scalar>,
    out: Vec<RistrettoPoint>,
    m: String,
    signers: Committee,
) -> (RistrettoPoint, Scalar) {
    let rho_i = musig_coef(signers.clone(), signer.public_key.key);
    let tilde_y = key_agg(signers.clone()).unwrap();

    let b = hash_non(signers.clone(), out.clone(), m.clone());
    // hash b_pre with sha512

    // prod = out[j]^(b^(j-1))
    let mut big_r = RistrettoPoint::identity();
    for (j, _) in out.iter().enumerate() {
        let bpowj = scalar_pow(b, j as u32);
        // make bpowj a scalar

        big_r += out[j] * bpowj;
    }

    // compute challenge
    // let c = hash_sig(tilde_y, big_r, m);
    let c = hash_sig(signers.public_key, big_r, m);
    // println!("c in signon: {:?}", c);



    // println!("HASHING SIGNATURE ON HASHON! {:?}", c);
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
    let lagrange_coeff = compute_lagrange_coefficient(signers, signer.id);

    // let z_1 = c * signer.private_key.get_key() * (lagrange_coeff +rho_i) + rhf;
    // println!("rho_i from {}: \n {:?}", signer.id, rho_i);
    // Test weird bugs with big t and n
    let z_1 = c * signer.private_key.get_key() * (lagrange_coeff) + rhf;

    (big_r, z_1)
}

fn scalar_pow(base: Scalar, exp: u32) -> Scalar {
    let mut result = Scalar::one();
    for _ in 0..exp {
        result *= base;
    }
    result
}

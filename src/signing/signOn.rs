use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use super::super::client::Client;
use super::super::util::*;

use crate::signing::keyAgg::key_agg;
use crate::signing::muSigCoef::musig_coef;

pub fn sign_on(
    // signer: Signer,
    signer: Client,
    state1: Vec<Scalar>,
    out: Vec<RistrettoPoint>,
    m: String,
    signers: Committee,
) -> (RistrettoPoint, Scalar) {
    let rho_i = musig_coef(signers.clone(), signer.pubkey);
    let tilde_y = key_agg(signers.clone()).unwrap();

    let b = hash_non(tilde_y, out.clone(), m.clone());
    // hash b_pre with sha512

    // prod = out[j]^(b^(j-1))
    let mut tilde_R = RistrettoPoint::identity();
    for (j, _) in out.iter().enumerate() {
        let bpowj = scalar_pow(b, j as u32);
        // make bpowj a scalar

        tilde_R += out[j] * bpowj;
    }

    // compute challenge
    // let c = hash_sig(tilde_y, big_r, m);
    let c = hash_sig(signer.vehkey, tilde_R, m);
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

    let z_1 = c * signer.get_share() * (lagrange_coeff + rho_i) + rhf; // c * signer.private_key.get_key() * (lagrange_coeff +rho_i) + rhf;
                                                                       // println!("rho_i from {}: \n {:?}", signer.id, rho_i);

    (tilde_R, z_1)
}

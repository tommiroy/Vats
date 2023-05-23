use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use super::super::client::Client;
use super::super::util::*;
use super::tilde_r;
use ::log::*;

use crate::signing::keyAgg::key_agg;
// use crate::signing::muSigCoef::musig_coef;

pub fn sign_on(
    // signer: Signer,
    signer: Client,
    state1: Vec<Scalar>,
    out: Vec<RistrettoPoint>,
    m: String,
    signers: Committee,
    outi: Vec<RistrettoPoint>,
) -> (RistrettoPoint, (Scalar, RistrettoPoint)) {
    let rho_i = musig_coef(signers.clone(), signer.pubkey);

    // println!("signOn's committee: {:?}", signers.signers.keys());
    let tilde_y = key_agg(signers.clone()).unwrap();


    let b = hash_non(tilde_y, out.clone(), m.clone());

    // hash b_pre with sha512
    // prod = out[j]^(b^(j-1))
    // let mut tilde_R = RistrettoPoint::identity();
    // for (j, _) in out.iter().enumerate() {
    //     let bpowj = scalar_pow(b, j as u32);
    //     // make bpowj a scalar

    //     tilde_R += out[j] * bpowj;
    // }

    let tilde_R = eval_poly_rist(b, out);
    // let tilde_R = eval_poly_rist(b, out);

    // let mut bigR_i = RistrettoPoint::identity();
    // for (j, _) in outi.iter().enumerate() {
    //     let bpowj = scalar_pow(b, j as u32);
    //     // make bpowj a scalar

    //     bigR_i += outi[j] * bpowj;
    // }

    let bigR_i = eval_poly_rist(b, outi);

    let c = hash_sig(signer.vehkey, tilde_R, m);


    // make z_1

    // let mut rhf = Scalar::zero();
    // for (j, _) in out.iter().enumerate() {
    //     let bpowj = scalar_pow(b, j as u32);
    //     // make bpowj a scalar
    //     let temp = state1[j] * bpowj;
    //     // make rhf to Scaler
    //     rhf += temp;
    // }
    let rhf = eval_poly(b, state1);
    // calculate z_1
    let lagrange_coeff = compute_lagrange_coefficient(signers, signer.id);

    let z_i = c * signer.get_share() * (lagrange_coeff + rho_i) + rhf; 

    (tilde_R, (z_i, bigR_i))
}

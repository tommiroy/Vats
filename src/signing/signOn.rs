use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use super::super::client::Client;
use super::super::util::*;
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

    println!("signOn's committee: {:?}", signers.signers.keys());
    let tilde_y = key_agg(signers.clone()).unwrap();

    println!("tilde_y: {}", point_to_string(tilde_y));
    let print_out = out
        .iter()
        .map(|point| point_to_string(*point))
        .collect::<String>();
    println!("out_list: {print_out:?}");

    let b = hash_non(tilde_y, out.clone(), m.clone());
    println!("b in signon:{}", scalar_to_string(&b));
    // hash b_pre with sha512

    // prod = out[j]^(b^(j-1))
    let mut tilde_R = RistrettoPoint::identity();
    for (j, _) in out.iter().enumerate() {
        let bpowj = scalar_pow(b, j as u32);
        // make bpowj a scalar

        tilde_R += out[j] * bpowj;
    }
    let mut bigR_i = RistrettoPoint::identity();
    for (j, _) in outi.iter().enumerate() {
        let bpowj = scalar_pow(b, j as u32);
        // make bpowj a scalar

        bigR_i += outi[j] * bpowj;
    }

    //println!("big_r in signon: {}", point_to_string(big_r));
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

    let z_i = c * signer.get_share() * (lagrange_coeff + rho_i) + rhf; // c * signer.private_key.get_key() * (lagrange_coeff +rho_i) + rhf;

    warn!("rho_i {:?}", scalar_to_string(&rho_i));
    warn!("bigR_i {:?}", point_to_string(bigR_i));
    warn!("z_i {:?}", scalar_to_string(&z_i));
    warn!("c_i {:?}", scalar_to_string(&c));
    warn!("lambda_i {:?}", scalar_to_string(&lagrange_coeff));
    warn!("tilde_r {:?}", point_to_string(tilde_R));
    (tilde_R, (z_i, bigR_i))
}

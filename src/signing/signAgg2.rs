use curve25519_dalek::scalar::Scalar;

use super::super::server::Server;
use super::super::util::*;
use super::tilde_r::calculate_tilde_r;
// use ::log::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;

pub fn sign_agg2(server: &Server) -> Result<(RistrettoPoint, Scalar), Vec<u32>> {
    let mut cheaters = Vec::<u32>::new();
    let committee = Committee::new(server.committee.clone());
    let tilde_r = calculate_tilde_r(committee.clone(), server.out.clone(), server.m.clone());
    let mut z = Scalar::zero();

    for signer in server.committee.keys().clone() {
        let &(tilde_rx, (big_rx, zx)) = server.partial_sigs.get(signer).unwrap();
        if tilde_r != tilde_rx {
            cheaters.push(*signer);
        }
        let &big_yx = server
            .pubkeys
            .get(signer)
            .expect("signAgg2: Cannot find pubkey for this signer");
        let rho_x = musig_coef(committee.clone(), big_yx);
        let lambda_x = compute_lagrange_coefficient(committee.clone(), *signer);
        let c_x = hash_sig(server.vehkey, tilde_rx, server.m.clone());
        let ver = &RISTRETTO_BASEPOINT_TABLE * &zx;
        if ver != big_rx + big_yx * (c_x * (rho_x + lambda_x)) {
            cheaters.push(*signer);
        } else {
            z += zx;
        }
    }
    if !cheaters.is_empty() {
        Err(cheaters)
    } else {
        Ok((tilde_r, z))
    }
}

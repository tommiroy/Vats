use super::super::util::*;
use super::keyAgg::key_agg;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;

pub fn calculate_tilde_r(com: Committee, out: Vec<RistrettoPoint>, m: String) -> RistrettoPoint {
    let tilde_y = key_agg(com).unwrap();

    let b = hash_non(tilde_y, out.clone(), m.clone());

    // let mut tilde_r = RistrettoPoint::identity();
    // for (j, _) in out.iter().enumerate() {
    //     let bpowj = scalar_pow(b, j as u32);
    //     tilde_r += out[j] * bpowj;
    // }

    let tilde_r = eval_poly_rist(b, out);
    tilde_r
}

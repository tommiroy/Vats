use super::super::util::*;
use super::keyAgg::key_agg;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;

pub fn tilde_r(com: Committee, out: Vec<RistrettoPoint>, m: String) -> RistrettoPoint {
    let tilde_y = key_agg(com.clone()).unwrap();

    let b = hash_non(tilde_y, out.clone(), m.clone());
    let mut tilde_R = RistrettoPoint::identity();
    for (j, _) in out.iter().enumerate() {
        let bpowj = scalar_pow(b, j as u32);
        tilde_R += out[j] * bpowj;
    }
    tilde_R
}

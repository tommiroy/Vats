use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use super::header::*;
use super::keyAgg::key_agg;

pub fn ver(
    m: String,
    big_y: RistrettoPoint,
    signature: (RistrettoPoint, Scalar),
    committee: Committee,
) -> bool {
    let c = hash_sig(big_y, signature.0, m);
    // println!("c in verfication: {:?}", c);

    let tilde_y = key_agg(committee).unwrap();

    let rhs = (tilde_y + big_y) * c + signature.0; //(tilde_y + big_y)* c + signature.0;
    let lhs = &RISTRETTO_BASEPOINT_TABLE * &signature.1;
    lhs == rhs
}

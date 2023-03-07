use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use super::header::*;

pub fn ver(m: String, tilde_y: RistrettoPoint, signature: (RistrettoPoint, Scalar)) -> bool {
    let c = hash_sig(tilde_y, signature.0, m);
    // println!("c in verfication: {:?}", c);

    let rhs = tilde_y * c + signature.0;
    let lhs = &RISTRETTO_BASEPOINT_TABLE * &signature.1;
    if lhs == rhs {
        println!("\nSignature Verified : Success");
        true
    } else {
        println!(
            "Signature Verification Failed: \n SHOULD BE :::::::::::: {:?} \n GOT :::::::::: {:?} \n",
            rhs, lhs
        );
        false
    }
}

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use super::signOn::hash_sig;

pub fn ver(m: String, pk_lambda: RistrettoPoint, signature: (RistrettoPoint, Scalar)) -> bool {
    let c = hash_sig(pk_lambda, signature.0, m);
    let rhs = signature.0 + (pk_lambda * c);
    // make Scalar in to RistrettoPoint
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

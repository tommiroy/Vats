use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use super::header::*;

pub fn ver(m: String, big_y: RistrettoPoint, signature: (RistrettoPoint, Scalar), committee:Committee) -> bool {
    let c = hash_sig(big_y, signature.0, m);
    // println!("c in verfication: {:?}", c);

    let mut tilde_y = RISTRETTO_BASEPOINT_POINT;
    for signer in committee.signers {
        tilde_y += signer.public_key.key;
    }

    tilde_y -= RISTRETTO_BASEPOINT_POINT;



    let rhs = tilde_y + big_y * c + signature.0;
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

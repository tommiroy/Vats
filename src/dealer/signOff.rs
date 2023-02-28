use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use futures::future::Shared;
use rand::rngs::OsRng;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};


// v is predefined for now. Read the paper for more info. 

const V:u8 = 2; 


pub fn signOff() -> (Vec<RistrettoPoint>, Vec<Scalar>){
    let mut rng: OsRng = OsRng;

    // For local signer of ID i
    // v has to be predefined. 
    let mut vs:Vec<Scalar> = Vec::with_capacity(V.into());
    let mut Rs:Vec<RistrettoPoint> = Vec::with_capacity(V.into());

    for _ in 0..V {
        let r = Scalar::random(&mut rng);
        vs.push(r.clone());
        Rs.push(&RISTRETTO_BASEPOINT_TABLE * &r)
    }
    (Rs, vs)
}
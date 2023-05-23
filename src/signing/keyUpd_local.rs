use std::collections::HashMap;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use curve25519_dalek::traits::Identity;
use log::*;
use rand::rngs::OsRng;

use super::super::client::Client;
use super::super::util::*;





pub fn update_share(signer:&mut Client, t: usize, context: String) -> ( HashMap<u32, Scalar>, Vec<RistrettoPoint>){
    let mut rng: OsRng = OsRng;

    // Dealer samples t random values t-1 a   ----> t = 3
    let mut a: Vec<Scalar> = Vec::with_capacity(t);
    a.push(signer.get_share());
    for _ in 1..t {
        a.push(Scalar::random(&mut rng));
    }

    // println!("Secret in keygen: {:?}", a[0]);

    // Calculate the shares    // Dealer samples t random values t-1 a   ----> t = 3

    let mut new_shares = HashMap::<u32, Scalar>::new();
    for &i in signer.pubkeys.keys() {      

        let f_ix = eval_poly(Scalar::from(i), a.clone());
        
        // TEST
        info!("New share to {}: {}", i, scalar_to_string(&f_ix.clone()));
        new_shares.insert(i, f_ix);

    }

    let k = Scalar::random(&mut rng);
    
    // Compute Response R = G^k
    let big_ri = &RISTRETTO_BASEPOINT_TABLE * &k;
    
    // Compute Challange c = H(i,Context,g^a_{i0}, Ri)
    let ci: Scalar = hash_key(signer.id, context.clone(), (&RISTRETTO_BASEPOINT_TABLE * &a[0]), big_ri);
    
    // Compute mu = k + a_{i0} * ci&
    let zi = k + a[0] * ci;

    // Generate the public commitments which will be broadcasted 0<=j<=t
    let mut big_as: Vec<RistrettoPoint> = Vec::with_capacity(t-1);
    for aj in a.iter() {
        big_as.push(&RISTRETTO_BASEPOINT_TABLE * aj);
    }

    // Return big_as and new_shares
    (new_shares, big_as)

}

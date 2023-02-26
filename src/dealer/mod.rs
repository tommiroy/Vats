use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use flume::Receiver;
use rand::rngs::OsRng;

use crate::dealer::dumb_keygen::reconstruct_secret_key;

mod dumb_keygen;

pub fn bl()  {
    // Example usage
    let t = 3; // threshold
    let n = 5; // number of participants

    let (sk, pk) = dumb_keygen::keygen(t, n);

    println!("Secret shares:");
    for i in 0..n {
        println!("s_{} = {:?}", i+1, sk[i].to_bytes());
    }

    println!("Public keys:");
    for i in 0..n {
        println!("pk_{} = {:?}", i+1, pk[i]);
    }

    // Verify the keys
    println!("Reconstructed shares {:?}",dumb_keygen::reconstruct_secret_key(&sk).to_bytes());

}

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use flume::Receiver;
use rand::rngs::OsRng;
use sha2::digest::typenum::private::PrivateIntegerAdd;

mod dumb_keygen;

pub fn bl() {
    // Example usage
    let t = 3; // threshold
    let n = 5; // number of participants

    let (sks, pks, pk) = dumb_keygen::keygen(t, n);

    // println!("Secret shares:");
    // for i in 0..n {
    //     println!("s_{} = {:?}", i + 1, sks[i].1.to_bytes());
    // }

    // println!("Public keys:");
    // for i in 0..n {
    //     println!("pk_{} = {:?}", i + 1, pks[i]);
    // }

    //make list with index and share

    use rand::{seq::SliceRandom, thread_rng};

    // pick random elements from a Vec<(u32, Scalar)>
    fn pick_random_elements<T: Clone>(list: Vec<T>, n: usize) -> Vec<T> {
        let mut rng = thread_rng();
        let mut list = list;
        list.shuffle(&mut rng);
        list.truncate(n);
        list
    }

    for i in 0..5 {
        let test_list = pick_random_elements(sks.clone(), t);
        dumb_keygen::reconstruct_secret_key(test_list.clone(), pk);
        println!("Reconstructing secret key suceeded, try {}", i + 1);
    }

    // lagrange interpolation to reconstruct the secret key with Scaler
    // let mut sk = Scalar::zero();
    // for i in 0..n {
    //     let mut l = Scalar::one();
    //     for j in 0..n {
    //         if i != j {
    //             l *= Scalar::from((j + 1) as u32) / (Scalar::from((j + 1) as u32) - Scalar::from((i + 1) as u32));
    //         }
    //     }
    //     sk += &sks[i].1 * &l;
    // }
}

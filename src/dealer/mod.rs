use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use flume::Receiver;
use rand::rngs::OsRng;
use sha2::digest::typenum::private::PrivateIntegerAdd;

use crate::dealer::signAgg::signAgg;
use crate::dealer::signOff::signOff;

mod keyAgg;
mod keygen;
mod muSigCoef;
mod signAgg;
mod signAgg2;
mod signOff;
mod signOn;
mod verification;

pub fn bl() {
    // Example usage
    let t = 3; // threshold
    let n = 5; // number of participants.clone()
    let v = 2; // number of nonces

    let (sks, pks, pk) = keygen::keygen(t, n);

    let participants = vec![1, 2, 3, 4, 5];
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

    //keygen::reconstruct_secret_key(sks.clone(), pk);
    for i in 0..10 {
        let test_list = pick_random_elements(sks.clone(), t);
        keygen::reconstruct_secret_key(test_list.clone(), pk);
        println!("Reconstructing secret key suceeded, try {}", i + 1);
    }
    // Works until here confirmed...
    //
    let _hash = muSigCoef::muSigCoef(pks.clone(), pks[0]);
    //
    let _hash2 = muSigCoef::muSigCoef(pks.clone(), pks[1]);
    //
    let _keyagg = keyAgg::keyAgg(pks.clone());
    //
    let signoff = signOff::signOff(v);
    //
    let _signagg = signAgg::signAgg(signoff.clone().1, v);
    //
    let lagrange_coeff = signOn::compute_lagrange_coefficient(sks.clone(), 1);
    let lagrange_coeff_1 = signOn::compute_lagrange_coefficient(sks.clone(), 2);
    let lagrange_coeff_2 = signOn::compute_lagrange_coefficient(sks.clone(), 3);
    let lagrange_coeff_3 = signOn::compute_lagrange_coefficient(sks.clone(), 4);
    let lagrange_coeff_4 = signOn::compute_lagrange_coefficient(sks.clone(), 5);
    println!("Lagrange coefficients for 1:  \n  {:?}\n", lagrange_coeff);
    println!("Lagrange coefficients for 2:  \n  {:?}\n", lagrange_coeff_1);
    println!("Lagrange coefficients for 3:  \n  {:?}\n", lagrange_coeff_2);
    println!("Lagrange coefficients for 4:  \n  {:?}\n", lagrange_coeff_3);
    println!("Lagrange coefficients for 5:  \n  {:?}\n", lagrange_coeff_4);
    println!("shares \n  {:?}\n", sks);
    let signon = signOn::SignOn(
        signoff.1.clone(),
        signoff.0.clone(),
        "Hello World".to_string(),
        sks[0],
        pks.clone()[0],
        pks.clone(),
        lagrange_coeff,
    );
    let signon_1 = signOn::SignOn(
        signoff.1.clone(),
        signoff.0.clone(),
        "Hello World".to_string(),
        sks[1],
        pks.clone()[1],
        pks.clone(),
        lagrange_coeff_1,
    );
    let signon_2 = signOn::SignOn(
        signoff.1.clone(),
        signoff.0.clone(),
        "Hello World".to_string(),
        sks[2],
        pks.clone()[2],
        pks.clone(),
        lagrange_coeff_2,
    );
    let signon_3 = signOn::SignOn(
        signoff.1.clone(),
        signoff.0.clone(),
        "Hello World".to_string(),
        sks[3],
        pks.clone()[3],
        pks.clone(),
        lagrange_coeff_3,
    );
    let signon_4 = signOn::SignOn(
        signoff.1.clone(),
        signoff.0,
        "Hello World".to_string(),
        sks[4],
        pks.clone()[4],
        pks,
        lagrange_coeff_4,
    );
    let mut z_list = Vec::with_capacity(n);
    z_list.push(signon.1);
    z_list.push(signon_1.1);
    z_list.push(signon_2.1);
    z_list.push(signon_3.1);
    z_list.push(signon_4.1);
    //
    //
    let signAgg2 = signAgg2::SignAgg2(z_list.clone());

    pub fn sign(state_prim: RistrettoPoint, out_prim: Scalar) -> (RistrettoPoint, Scalar) {
        (state_prim, out_prim)
    }

    let signature = sign(signon.0, signAgg2);
    //println!("Signing:  \n  {:?}\n", signature);
    ////ver(m: String, pk_lambda: RistrettoPoint, signature: (RistrettoPoint, Scalar)) -> bool
    verification::ver("Hello World".to_string(), signon.2, signature);
}

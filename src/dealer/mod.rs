use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use flume::Receiver;
use rand::rngs::OsRng;
use sha2::digest::typenum::private::PrivateIntegerAdd;

use crate::dealer::signAgg::signAgg;
use crate::dealer::signAgg::test_signagg;
use crate::dealer::signOff::signOff;
use rand::{seq::SliceRandom, thread_rng};

mod keyAgg;
mod keygen;
mod muSigCoef;
mod signAgg;
mod signAgg2;
mod signOff;
mod signOn;
mod verification;

pub fn bl() {
    muSigCoef::test_muSigCoef();
    // Example usage
    let t = 3; // threshold
    let n = 5; // number of participants.clone()
    let v = 2; // number of nonc
    let (sks, pks, pk) = keygen::keygen(t, n);

    let participants = vec![1, 2, 3, 4, 5];

    // pick random elements from a Vec<(u32, Scalar)>
    for i in 0..1000 {
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
        let mut sigagg_list = Vec::<(Vec<RistrettoPoint>)>::new();

        let signoff = signOff::signOff(v);
        let signoff_1 = signOff::signOff(v);
        let signoff_2 = signOff::signOff(v);
        let signoff_3 = signOff::signOff(v);
        let signoff_4 = signOff::signOff(v);

        sigagg_list.push(signoff.0);
        sigagg_list.push(signoff_1.0);
        sigagg_list.push(signoff_2.0);
        sigagg_list.push(signoff_3.0);
        sigagg_list.push(signoff_4.0);

        //
        let sigagg = signAgg::signAgg(sigagg_list.clone(), v);
        //
        let lagrange_coeff = signOn::compute_lagrange_coefficient(sks.clone(), 1);
        let lagrange_coeff_1 = signOn::compute_lagrange_coefficient(sks.clone(), 2);
        let lagrange_coeff_2 = signOn::compute_lagrange_coefficient(sks.clone(), 3);
        let lagrange_coeff_3 = signOn::compute_lagrange_coefficient(sks.clone(), 4);
        let lagrange_coeff_4 = signOn::compute_lagrange_coefficient(sks.clone(), 5);

        let signon = signOn::SignOn(
            signoff.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[0],
            pks.clone()[0],
            pks.clone(),
            lagrange_coeff,
        );
        let signon_1 = signOn::SignOn(
            signoff_1.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[1],
            pks.clone()[1],
            pks.clone(),
            lagrange_coeff_1,
        );
        let signon_2 = signOn::SignOn(
            signoff_2.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[2],
            pks.clone()[2],
            pks.clone(),
            lagrange_coeff_2,
        );
        let signon_3 = signOn::SignOn(
            signoff_3.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[3],
            pks.clone()[3],
            pks.clone(),
            lagrange_coeff_3,
        );
        let signon_4 = signOn::SignOn(
            signoff_4.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[4],
            pks.clone()[4],
            pks.clone(),
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

        assert_eq!(signon.0, signon_1.0, "signon.0 != signon_1.0");

        let signature = sign(signon_4.0, signAgg2);
        //println!("Signing:  \n  {:?}\n", signature);
        ////ver(m: String, pk_lambda: RistrettoPoint, signature: (RistrettoPoint, Scalar)) -> bool
        verification::ver("Hello World".to_string(), signon.2, signature);
    }
}

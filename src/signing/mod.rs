use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::signing::signAgg::sign_agg;
use crate::signing::signAgg::test_signagg;
use crate::signing::signOff::signOff;
use rand::{seq::SliceRandom, thread_rng};

use vats::dealer;
mod keyAgg;
mod muSigCoef;
mod signAgg;
mod signAgg2;
mod signOff;
mod signOn;
mod verification;

mod header;

pub fn bl() {
    // Example usage
    let t = 3; // threshold
    let n = 5; // number of participants.clone()
    let v = 2; // number of nonce
    let (sks, pks) = dealer::keygen(t, n);

    let participants = vec![1, 2, 3, 4, 5];

    // pick random elements from a Vec<(u32, Scalar)>
    for i in 0..1 {
        fn pick_random_elements<T: Clone>(list: Vec<T>, n: usize) -> Vec<T> {
            let mut rng = thread_rng();
            let mut list = list;
            list.shuffle(&mut rng);
            list.truncate(n);
            list
        }

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
        let sigagg = signAgg::sign_agg(sigagg_list.clone(), v);
        //
        let lagrange_coeff = header::compute_lagrange_coefficient(participants.clone(), 1);
        let lagrange_coeff_1 = header::compute_lagrange_coefficient(participants.clone(), 2);
        let lagrange_coeff_2 = header::compute_lagrange_coefficient(participants.clone(), 3);
        let lagrange_coeff_3 = header::compute_lagrange_coefficient(participants.clone(), 4);
        let lagrange_coeff_4 = header::compute_lagrange_coefficient(participants.clone(), 5);

        let signon = signOn::SignOn(
            signoff.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[0],
            pks.clone()[0],
            pks.clone(),
            lagrange_coeff,
            participants.clone(),
        );
        let signon_1 = signOn::SignOn(
            signoff_1.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[1],
            pks.clone()[1],
            pks.clone(),
            lagrange_coeff_1,
            participants.clone(),
        );
        let signon_2 = signOn::SignOn(
            signoff_2.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[2],
            pks.clone()[2],
            pks.clone(),
            lagrange_coeff_2,
            participants.clone(),
        );
        let signon_3 = signOn::SignOn(
            signoff_3.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[3],
            pks.clone()[3],
            pks.clone(),
            lagrange_coeff_3,
            participants.clone(),
        );
        let signon_4 = signOn::SignOn(
            signoff_4.1.clone(),
            sigagg.clone(),
            "Hello World".to_string(),
            sks[4],
            pks.clone()[4],
            pks.clone(),
            lagrange_coeff_4,
            participants.clone(),
        );

        //check if all same tilde_y
        assert_eq!(signon.2, signon_1.2, "signon.1 != signon_1.1");

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

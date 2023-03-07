use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::prelude::*;

use vats::dealer;
mod keyAgg;
mod keyUpd;
mod muSigCoef;
mod signAgg;
mod signAgg2;
mod signOff;
mod signOn;
mod verification;

mod header;
use crate::signing::header::*;

pub fn bl() {
    // Example usage
    let t = 3; // threshold
    let n = 5; // number of participants.clone()
    let v = 2; // number of nonce
    let (sks, pks, pk, sk) = dealer::keygen(t, n);

    // Make a list of all participants and give them the right share
    let mut participants = Vec::<Signer>::new();
    for (i, sk) in sks.iter().enumerate() {
        let pubkey = PublicKey::new(pks[i].0, pks[i].1);
        let prikey = PrivateKey::new(sk.0, sk.1);
        participants.push(Signer::new(sk.0, prikey, pubkey));
    }
    // List of all signers (a partition of participan)
    let mut committee = Committee::new(vec![
        participants[1].clone(),
        participants[2].clone(),
        participants[3].clone(),
        participants[4].clone(),
        participants[0].clone(),
    ]);

    pub fn random_committee(committee: Committee, t: usize) -> Committee {
        let mut rng = rand::thread_rng();
        let mut shuffled = committee.signers.clone();
        shuffled.shuffle(&mut rng);
        Committee::new(shuffled.into_iter().take(t).collect())
    }

    committee = random_committee(committee, t);

    // for testing purposes of threshold
    //committee = random_committee(committee, t-1);

    //print what ids that are in the committee
    for signer in committee.clone().signers {
        println!("Signer id: {}", signer.id);
    }

    committee.set_public_key(pk);

    let mut outs = Vec::with_capacity(n);
    let mut states = Vec::with_capacity(n);

    // Checked outs and states
    for _ in committee.signers.clone() {
        let (out, state) = signOff::sign_off(v);
        outs.push(out);
        states.push(state);
    }

    let sign_agg = signAgg::sign_agg(outs.clone(), v);

    let mut big_rs = Vec::with_capacity(n);
    let mut zs = Vec::with_capacity(n);

    for (i, signer) in committee.clone().signers.iter().enumerate() {
        let (big_r, zi) = signOn::sign_on(
            signer.clone(),
            states[i].clone(),
            sign_agg.clone(),
            "Super mega error message".to_string(),
            committee.clone(),
        );
        big_rs.push(big_r);
        zs.push(zi);
    }

    let tilde_y = keyAgg::key_agg(committee.clone()).unwrap();
    let mut big_ys = Vec::with_capacity(t);
    for signer in committee.clone().signers {
        big_ys.push(signer.public_key.key);
    }

    let sign_agg2 = signAgg2::signAgg2(zs.clone(), tilde_y, big_ys, committee.clone());

    let mut sk_prim = Scalar::zero();
    for signer in committee.clone().signers {
        sk_prim += signer.private_key.get_key()
            * compute_lagrange_coefficient(committee.clone(), signer.id);
    }

    // Secret key is correct!
    // assert_eq!(sk_prim, sk, "Reconstructed secret key and secret key is not equal in mod");
    // Check if reconstructed secret key is equal public key
    // assert_eq!(pk, &RISTRETTO_BASEPOINT_TABLE*&sk_prim, "Public key is not equal secret key");

    verification::ver(
        "Super mega error message".to_string(),
        pk,
        (big_rs[0], sign_agg2),
    );
}

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::prelude::*;

use vats::dealer;
mod keyAgg;
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
    let (sks, pks) = dealer::keygen(t, n);

    // Make a list of all participants and give them the right share
    let mut participants = Vec::<Signer>::new();
    for (i, sk) in sks.iter().enumerate() {
        let pubkey = PublicKey::new(pks[i].0, pks[i].1);
        let prikey = PrivateKey::new(sk.0, sk.1);
        participants.push(Signer::new(sk.0, prikey, pubkey));
    }
    // List of all signers (a partition of participan)
    let committee = Committee::new(vec![
        participants[1].clone(),
        participants[2].clone(),
        participants[3].clone(),
    ]);

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

    for (i, signer) in committee.signers.iter().enumerate() {
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

    let sign_agg2 = signAgg2::SignAgg2(zs.clone());

    let tilde_y = keyAgg::key_agg(committee).unwrap();

    verification::ver(
        "Super mega error message".to_string(),
        tilde_y,
        (big_rs[0], sign_agg2),
    );
}

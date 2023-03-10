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
mod key_update;
pub mod header;
use crate::signing::header::*;

pub fn bl() -> bool {
    // Example usage
    let t = 10; // threshold
    let n = 100; // number of participants.clone()
    let v = 5; // number of nonce
    let (sks, pks, pk, sk) = dealer::keygen(t, n);

    // Make a list of all participants and give them the right share
    let mut participants = Vec::<Signer>::new();
    for (i, sk) in sks.iter().enumerate() {
        let pubkey = PublicKey::new(pks[i].0, pks[i].1);
        let prikey = PrivateKey::new(sk.0, sk.1);
        participants.push(Signer::new(sk.0, prikey, pubkey));
    }

    let mut committee = Committee::new(participants);

    pub fn random_committee(committee: Committee, t: usize) -> Committee {
        let mut rng = rand::thread_rng();
        let mut shuffled = committee.signers;
        shuffled.shuffle(&mut rng);
        Committee::new(shuffled.into_iter().take(t).collect())
    }

    committee = random_committee(committee, t);



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

    let sign_agg2 = signAgg2::signAgg2(zs.clone(), committee.clone());

    let mut sk_prim = Scalar::zero();
    for signer in committee.clone().signers {
        sk_prim += signer.private_key.get_key()
            * compute_lagrange_coefficient(committee.clone(), signer.id);
    }

    assert_eq!(sk, sk_prim, "Key reconstruction is wrong");

    // Secret key is correct!
    // assert_eq!(sk_prim, sk, "Reconstructed secret key and secret key is not equal in mod");
    // Check if reconstructed secret key is equal public key
    // assert_eq!(pk, &RISTRETTO_BASEPOINT_TABLE*&sk_prim, "Public key is not equal secret key");

    verification::ver(
        "Super mega error message".to_string(),
        pk,
        (big_rs[0], sign_agg2),
        committee.clone(),
    )
}

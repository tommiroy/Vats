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





pub async fn update_share(signer:&mut Client, _participants: Vec<u32>, t: usize, context: String) -> bool{
    let mut rng: OsRng = OsRng;

    // Dealer samples t random values t-1 a   ----> t = 3
    let mut a: Vec<Scalar> = Vec::with_capacity(t);
    a.push(signer.get_share());
    for _ in 1..(t-1) {
        a.push(Scalar::random(&mut rng));
    }

    // println!("Secret in keygen: {:?}", a[0]);

    // Calculate the shares    // Dealer samples t random values t-1 a   ----> t = 3
    // Dealer samples t random values t-1 a   ----> t = 3

    let mut new_shares = HashMap::<u32, Scalar>::new();
    for &i in signer.pubkeys.keys() {
        let mut share = Scalar::zero();
        for (j, &aj) in a.iter().enumerate() {
            share += aj * scalar_pow(Scalar::from(i as u32), j as u32);
        }
        new_shares.insert(i, share);
    }

    // Generate the public commitments which will be broadcasted 0<=j<=t
    let mut big_as = Vec::with_capacity(t-1);
    for aj in a.iter() {
        big_as.push(&RISTRETTO_BASEPOINT_TABLE * aj);
    }

    // signer.commitments.insert(signer.id, big_as.clone());
    // Generate Nonce k
    let k = Scalar::random(&mut rng);

    // Compute Response R = G^k
    let big_ri = &RISTRETTO_BASEPOINT_TABLE * &k;

    // Compute Challange c = H(i,Context,g^a_{i0}, Ri)
    let ci: Scalar = hash_key(signer.id, context.clone(), big_as[0], big_ri);
    warn!("update_share: my_pubkey_{} {}", signer.id, point_to_string(signer.pubkey));

    warn!("update_share: c_{} {}", signer.id, scalar_to_string(&ci));
    warn!("update_share: context_{} {}", signer.id, context.clone());
    warn!("update_share: pubkey_{} {}", signer.id, point_to_string(big_as[0]));
    warn!("update_share: big_ri{} {}", signer.id, point_to_string(big_ri));

    // Compute mu = k + a_{i0} * ci
    let zi = k + a[0] * ci;
    // warn!("rhs{}: {}", signer.id, point_to_string(&RISTRETTO_BASEPOINT_TABLE*&zi.clone()));
    // warn!("lhs{} {}", signer.id, point_to_string(big_ri+big_as[0]*ci));



    // Broadcast commitments and signature
    let mut msg_body = Vec::<String>::new();
    // commitments.iter().for_each(|commitment| msg_body.push(point_to_string(*commitment)));
    msg_body.push(point_to_string(big_ri));
    msg_body.push(scalar_to_string(&zi));
    let _: Vec<_> = big_as.iter().map(|big_a| msg_body.push(point_to_string(*big_a))).collect();
    // warn!("Length of a: {}", a.len());
    // warn!("Length of big_as: {}", big_as.len());
    // warn!("Length of body: {}", msg_body.len());

    let msg = Message {sender: signer.id.to_string(), receiver: "broadcast".to_string(), msg_type: MsgType::KeyUpdCommitment, msg: msg_body};
    signer.send("keyupd_commitment".to_owned(), msg).await;
    // info!("Sent commitments");


    // -------------------------- ROUND 2 ----------------------------------------

    for &participant in signer.pubkeys.keys() {
        if new_shares.contains_key(&participant) {
            let msg: Message = Message {sender: signer.id.to_string(), receiver: participant.to_string(), msg_type: MsgType::KeyUpdNewShare, msg: vec![scalar_to_string(new_shares.get(&participant).expect("keyUpd: Cannot find participant"))]};
            signer.send("keyupd_newshare".to_string(), msg).await;
        }

        let mut rhs = RistrettoPoint::identity();
        for (k, &big_a) in big_as.iter().enumerate() {
            rhs += big_a*scalar_pow(Scalar::from(participant), k as u32);
        }


        // warn!("Gen-lhs of {} for {}: {}", signer.id, participant.to_string(),  point_to_string(&RISTRETTO_BASEPOINT_TABLE * new_shares.get(&participant).unwrap()));
        // warn!("Gen-rhs of {} for {}: {}", signer.id, participant.to_string(),  point_to_string(rhs));


    }


    // info!("Sent new shares");

    true

}

pub fn verify_sigma(me: &Client, sigma: (RistrettoPoint, Scalar), context_string: String, sender_id: u32) -> bool {
    let (big_r, zx) = sigma;
    // warn!("zi_{}: {}", sender_id, scalar_to_string(&zx.clone()));
    
    let c = hash_key(sender_id, context_string.clone(), *me.pubkeys.get(&sender_id).expect("keyUpd-verify_sigma: Cannot find sender_id in pubkeys"), big_r.clone());
    
    // warn!("verify_sigma: big_ri_{} {}", sender_id, point_to_string(big_r));
    // warn!("verify_sigma: rhs_{}: {}", sender_id, point_to_string(&RISTRETTO_BASEPOINT_TABLE * &zx + *me.pubkeys.get(&sender_id).expect("keyUpd-verify_sigma: Cannot find sender_id in pubkeys")*(-c)));
    let res = big_r == &RISTRETTO_BASEPOINT_TABLE * &zx + *me.pubkeys.get(&sender_id).expect("keyUpd-verify_sigma: Cannot find sender_id in pubkeys")*(-c);

    if !res {

        warn!("verify_sigma: c_{} {}", sender_id, scalar_to_string(&c));
        warn!("verify_sigma: context_string_{}: {}",sender_id, context_string);
        warn!("verify_sigma: pubkey_{} {}", sender_id, point_to_string(*me.pubkeys.get(&sender_id).expect("keyUpd-verify_sigma: Cannot find sender_id in pubkeys")));
        warn!("verify_sigma: big_ri_{} {}", sender_id, point_to_string(big_r));      
        panic!("Faulty COMMITMENT")
    }
    res
}


pub fn verify_new_share(me: &mut Client, sender_id: u32, new_share: Scalar) {
    let mut rhs = RistrettoPoint::identity();
    if me.commitments.contains_key(&sender_id) {
        // for (k, &big_a) in me.commitments.get(&sender_id).iter().enumerate() {
        // warn!("Found commitment from {sender_id}");
        for (k, &big_a) in me.commitments.get(&sender_id).expect("keyUpd-verify_new_share: cannot get id").iter().enumerate() {
            rhs += big_a*scalar_pow(Scalar::from(me.id), k as u32);
        }

    } else {
        // warn!("Not Found commitment from {sender_id}");
    }

    // warn!("Verification-lhs of {}: {}",sender_id,  point_to_string(&RISTRETTO_BASEPOINT_TABLE * &new_share));
    // warn!("Verification-rhs of {}: {}",sender_id,  point_to_string(rhs));

    if &RISTRETTO_BASEPOINT_TABLE * &new_share == rhs {
        // me.set_share(me.get_share()+ new_share*compute_lagrange_coefficient(Committee::new(me.pubkeys.clone()), me.id));
        // me.pubkey = &RISTRETTO_BASEPOINT_TABLE * &me.get_share();
        // me.pubkeys.insert(me.id,me.pubkey);
        info!("New Share from {sender_id} added");
    } else {
        info!("Cannot add new share from {sender_id}");
    }
}


pub fn update_pubkeys(me: &mut Client) {
    let com = Committee::new(me.pubkeys.clone());
    let mut new_pubkeys: HashMap<u32, RistrettoPoint> = HashMap::<u32, RistrettoPoint>::new();
    for &x in me.pubkeys.keys().clone() {
        let mut new_pubkey = RistrettoPoint::default();
        for (j, pubkey) in me.pubkeys.clone() {
            if me.commitments.contains_key(&x) {
                let mut temp = RistrettoPoint::default();
                for (k, big_a) in me.commitments.get(&x).expect("keyUpd-update_pubkeys: cannot get id").iter().enumerate() {
                    temp += big_a*Scalar::from(x)*Scalar::from(k as u32);
                }
                new_pubkey += temp*compute_lagrange_coefficient(com.clone(), j);
            } else {
                new_pubkey += pubkey*compute_lagrange_coefficient(com.clone(), j)*Scalar::from(x);

            }
        }
        new_pubkeys.insert(x, new_pubkey);
    }
    me.pubkeys = new_pubkeys;
}

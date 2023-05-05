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





pub async fn update_share(signer:&mut Client, participants: Vec<u32>, t: usize, context: String) -> bool{
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
        let mut f_ix = Scalar::zero();
        for (j, &aj) in a.iter().enumerate() {
            f_ix += aj * scalar_pow(Scalar::from(i as u32), j as u32);
        }
        // TEST
        info!("New share to {}: {}", i, scalar_to_string(&f_ix.clone()));
        new_shares.insert(i, f_ix);
    }

    // TEST NEW SHARE GENERATION - GOOD
    let mut gen_share = Scalar::zero();
    for (id, share) in new_shares.clone() {
        gen_share += share*compute_lagrange_coefficient(Committee::new(signer.pubkeys.clone()), id);
    }

    assert_eq!(scalar_to_string(&gen_share), scalar_to_string(&signer.get_share().clone()));
    info!("######## New shares successfully generated ###########");

    // Manually add our share to the share message list in client
    let msg: Message = Message {sender: signer.id.to_string(), receiver: signer.id.to_string(), msg_type: MsgType::KeyUpdNewShare, msg: vec![scalar_to_string(new_shares.get(&signer.id).expect("keyUpd: Cannot find participant"))]};
    signer.new_share_msg.push(msg);
    
    // signer.commitments.insert(signer.id, big_as.clone());
    // Generate Nonce k
    let k = Scalar::random(&mut rng);
    
    // Compute Response R = G^k
    let big_ri = &RISTRETTO_BASEPOINT_TABLE * &k;
    
    // Compute Challange c = H(i,Context,g^a_{i0}, Ri)
    let ci: Scalar = hash_key(signer.id, context.clone(), (&RISTRETTO_BASEPOINT_TABLE * &a[0]), big_ri);
    // info!("update_share: my_pubkey_{} {}", signer.id, point_to_string(signer.pubkey));
    
    // info!("update_share: c_{} {}", signer.id, scalar_to_string(&ci));
    // info!("update_share: context_{} {}", signer.id, context.clone());
    // info!("update_share: pubkey_{} {}", signer.id, point_to_string(signer.pubkey));
    // info!("update_share: big_ri{} {}", signer.id, point_to_string(big_ri));
    
    // Compute mu = k + a_{i0} * ci&
    let zi = k + a[0] * ci;
    // warn!("rhs{}: {}", signer.id, point_to_string(&RISTRETTO_BASEPOINT_TABLE*&zi.clone()));
    // warn!("lhs{} {}", signer.id, point_to_string(big_ri+big_as[0]*ci));
    
    
    // Generate the public commitments which will be broadcasted 0<=j<=t
    let mut big_as: Vec<RistrettoPoint> = Vec::with_capacity(t-1);
    for aj in a.iter() {
        big_as.push(&RISTRETTO_BASEPOINT_TABLE * aj);
    }
    // signer.commitments.insert(signer.id, big_as.clone());


    // Broadcast commitments and sigma
    let mut msg_body = Vec::<String>::new();
    // commitments.iter().for_each(|commitment| msg_body.push(point_to_string(*commitment)));
    msg_body.push(point_to_string(big_ri));
    msg_body.push(scalar_to_string(&zi));
    let _: Vec<_> = big_as.iter().map(|big_a| msg_body.push(point_to_string(*big_a))).collect();
    // warn!("Length of a: {}", a.len());
    // warn!("Length of big_as: {}", big_as.len());
    // warn!("Length of body: {}", msg_body.len());

    // Broadcast commitments
    let msg = Message {sender: signer.id.to_string(), receiver: "broadcast".to_string(), msg_type: MsgType::KeyUpdCommitment, msg: msg_body};
    signer.send("keyupd_commitment".to_owned(), msg.clone()).await;
    signer.commitments_msg.push(msg);
    // info!("Sent commitments");


    // -------------------------- ROUND 2 ----------------------------------------

    // Send new share to respective participant
    for &participant in signer.pubkeys.keys() {
        if new_shares.contains_key(&participant) {
            let msg: Message = Message {sender: signer.id.to_string(), receiver: participant.to_string(), msg_type: MsgType::KeyUpdNewShare, msg: vec![scalar_to_string(new_shares.get(&participant).expect("keyUpd: Cannot find participant"))]};
            signer.send("keyupd_newshare".to_string(), msg).await;
            // TEST
            info!("Sent new share to {}: {}", participant, scalar_to_string(new_shares.get(&participant).unwrap()));
        }
    }

    true

}

pub fn verify_sigma(me: &Client, sigma: (RistrettoPoint, Scalar), big_a : RistrettoPoint, context_string: String, sender_id: u32) -> bool {
    let (big_r, zx) = sigma;
    // warn!("zi_{}: {}", sender_id, scalar_to_string(&zx.clone()));
    
    let c = hash_key(sender_id, context_string.clone(), big_a, big_r);
    
    // warn!("verify_sigma: big_ri_{} {}", sender_id, point_to_string(big_r));
    // warn!("verify_sigma: rhs_{}: {}", sender_id, point_to_string(&RISTRETTO_BASEPOINT_TABLE * &zx + *me.pubkeys.get(&sender_id).expect("keyUpd-verify_sigma: Cannot find sender_id in pubkeys")*(-c)));
    let res = big_r == &RISTRETTO_BASEPOINT_TABLE * &zx + big_a*(-c);

    if !res {
        info!("verify_sigma: c_{} {}", sender_id, scalar_to_string(&c));
        info!("verify_sigma: context_string_{}: {}",sender_id, context_string);
        info!("verify_sigma: pubkey_{} {}", sender_id, point_to_string(*me.pubkeys.get(&sender_id).expect("keyUpd-verify_sigma: Cannot find sender_id in pubkeys")));
        info!("verify_sigma: big_ri_{} {}", sender_id, point_to_string(big_r));      
        info!("Faulty COMMITMENT")
    }
    res
}


pub fn verify_new_share(me: &mut Client, sender_id: u32, new_share: Scalar) -> bool {
    let mut rhs = RistrettoPoint::identity();
    if me.commitments.contains_key(&sender_id) {
        // for (k, &big_a) in me.commitments.get(&sender_id).iter().enumerate() {
        // warn!("Found commitment from {sender_id}");
        for (k, &big_a) in me.commitments.get(&sender_id).expect("keyUpd-verify_new_share: cannot get id").iter().enumerate() {
            // rhs += big_a * Scalar::from(me.id) * Scalar::from(k as u32);
            rhs += big_a * scalar_pow(Scalar::from(me.id),k as u32);

        }

    } else {
        info!("Not Found commitment from {sender_id}");
    }

    &RISTRETTO_BASEPOINT_TABLE * &new_share == rhs
}


pub fn update_pubkeys(me: &mut Client) {
    let com = Committee::new(me.pubkeys.clone());
    let mut new_pubkeys: HashMap<u32, RistrettoPoint> = HashMap::<u32, RistrettoPoint>::new();
    for (x, pubkey) in me.pubkeys.clone() {
        if x == me.id {
            continue;
        }
        let mut new_pubkey = pubkey;
        for (j, _) in me.pubkeys.clone() {
            if j == me.id {
                continue;
            }
            let mut temp = RistrettoPoint::identity();
            for (k, big_a) in me.commitments.get(&x).expect("keyUpd-update_pubkeys: cannot get id").iter().enumerate() {
                temp += big_a*scalar_pow(Scalar::from(x), k as u32);
            }
            new_pubkey += temp*compute_lagrange_coefficient(com.clone(), j);
        }
        new_pubkeys.insert(x, new_pubkey);
    }
    me.pubkey = *me.pubkeys.get(&me.id).unwrap();
    info!("pubkeys updated after new shares");
}

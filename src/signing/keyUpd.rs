use std::collections::HashMap;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;

use super::super::client::Client;
use super::super::util::*;

pub async fn key_upd(signer: Client, participants: Vec<u32>, t: usize, n: usize, context: String) {
    let mut rng: OsRng = OsRng;

    // Dealer samples t random values t-1 a   ----> t = 3
    let mut a: Vec<Scalar> = Vec::with_capacity(t);
    a.push(signer.get_share());
    for _ in 1..t {
        a.push(Scalar::random(&mut rng));
    }

    // println!("Secret in keygen: {:?}", a[0]);

    // Calculate the shares    // Dealer samples t random values t-1 a   ----> t = 3
    // Dealer samples t random values t-1 a   ----> t = 3

    let mut new_shares = HashMap::<u32, Scalar>::new();
    for i in participants {
        let mut share = signer.get_share();
        for (j, &aj) in a.iter().enumerate() {
            share += aj * scalar_pow(Scalar::from(i as u32), j as u32);
        }
        new_shares.insert(i, share);
    }

    // Generate the commitments which will be broadcasted 0<=j<=t
    let mut big_as = Vec::with_capacity(t);
    for aj in a.iter() {
        big_as.push(&RISTRETTO_BASEPOINT_TABLE * aj);
    }

    // Generate Nonce k
    let k = Scalar::random(&mut rng);

    // Compute Response R = G^k
    let big_ri = &RISTRETTO_BASEPOINT_TABLE * &k;

    // Compute Challange c = H(i,Context,g^a_{i0}, Ri)
    let ci = hash_key(signer.id, context, big_as[0], big_ri);

    // Compute mu = k + a_{i0} * ci
    let zi = k + a[0] * ci;

    // Compute the public commitment
    // let commitments = Vec::with_capacity(t);

    // for i in 1..t {
    //     commitments.push(mini_sigma[i]);
    // }

    let sigma_i = (big_ri, zi);

    //------------------------------------Broadcast --------------------------------------

    let sigma_i_string = (point_to_string(sigma_i.0), scalar_to_string(&sigma_i.1));
    let mut commitments_string = Vec::with_capacity(t);
    for i in big_as.clone() {
        commitments_string.push(point_to_string(i));
    }

    // make sigma_i_string and commitments_string a string
    let sigma_i_string = serde_json::to_string(&sigma_i_string).unwrap();
    // make commitments_string a string
    let commitments_string = serde_json::to_string(&commitments_string).unwrap();

    println!("sigma_i_string: {}", sigma_i_string);
    println!("commitments_string: {}", commitments_string);

    //BROADCAST commitments, sigma = (big_r_i, mu_i);

    // ------------------------------------Test--------------------------------------

    //convert back to string
    let back_tostring_sigma_i = serde_json::from_str::<(String, String)>(&sigma_i_string).unwrap();
    let back_tostring_commitments =
        serde_json::from_str::<Vec<String>>(&commitments_string).unwrap();

    //convert back to RistrettoPoint and Scalar
    let back_to_point_sigma_i = string_to_point(&back_tostring_sigma_i.0).unwrap();
    let back_to_scalar_sigma_i = string_to_scalar(&back_tostring_sigma_i.1).unwrap();
    let mut back_to_point_commitments = Vec::with_capacity(t);
    for i in back_tostring_commitments {
        back_to_point_commitments.push(string_to_point(&i).unwrap());
    }

    //verify
    assert_eq!(
        sigma_i.0, back_to_point_sigma_i,
        "sigma_i.0: {:?}, back_to_point_sigma_i: {:?}",
        sigma_i.0, back_to_point_sigma_i
    );
    assert_eq!(
        sigma_i.1, back_to_scalar_sigma_i,
        "sigma_i.1: {:?}, back_to_scalar_sigma_i: {:?}",
        sigma_i.1, back_to_scalar_sigma_i
    );
    assert_eq!(
        commitments.clone(),
        back_to_point_commitments.clone(),
        "commitments: {:?}, back_to_point_commitments: {:?}",
        commitments,
        back_to_point_commitments
    );

    // ------------------------------------Test--------------------------------------

    //Upon receiving all commitments, verify sigma_l = (big_r_l, mu_l). 1<=l<=n l/=i
    //Verify that c_l = H(l,Context,g^a_{l0}, R_l)
    //Verify that R_l = G^mu_l * mini_sigma^-c_l
    //upon verification, Delete {minisigma_l, 1<=l<=n}

    // Round Two

    // (shares, pks, pk, a[0])
}

fn verify_sigma(sender: Client, sigma: (RistrettoPoint, Scalar), context_string: String) -> bool {
    let (big_r, mu) = sigma;
    let c = hash_key(sender.id, context_string, sender.pubkey, big_r);
    assert_eq!(
        big_r,
        &RISTRETTO_BASEPOINT_TABLE * &mu + sender.pubkey * c.invert(),
        "sigma is wrong in keyUpd"
    );
    true
}

use std::collections::HashMap;

use base64::{engine::general_purpose, Engine as _};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub const RISTRETTO_POINT_SIZE_IN_BYTES: usize = 32;
use sha2::{Digest, Sha512};

use crate::client::Client;

/// ######################################################
/// Read certificates for sending HTTPS request - reqwest
/// ######################################################

pub async fn reqwest_read_cert(path: String) -> Certificate {
    let mut buf = Vec::new();
    File::open(path)
        .await
        .unwrap()
        .read_to_end(&mut buf)
        .await
        .unwrap();
    reqwest::Certificate::from_pem(&buf).unwrap()
}

/// ######################################################
/// Generate identity for the request sender - reqwest
/// ######################################################

pub async fn get_identity(path: String) -> Identity {
    let mut buf = Vec::new();
    File::open(path)
        .await
        .unwrap()
        .read_to_end(&mut buf)
        .await
        .unwrap();
    reqwest::Identity::from_pem(&buf).unwrap()
}

// ######################################################
/// Message description
// ######################################################
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    // Should have sender and receiver anyways
    pub sender: String,
    pub receiver: String,
    //
    pub msg_type: MsgType,
    pub msg: Vec<String>,
}

// Different types of message sent over the network
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum MsgType {
    Keygen,
    Nonce,
    Sign,
    Update,
}

// ######################################################
/// Message description
// ######################################################

pub async fn reqwest_send(
    reqwest_client: reqwest::Client,
    receiver: String,
    channel: String,
    msg: Message,
) -> String {
    // Serialize the message
    let msg = serde_json::to_string(&msg).expect("Cant serialize this message");
    // Send it!
    // println!("{}", msg.clone());
    if let Ok(res) = reqwest_client
        .post("https://".to_owned() + &receiver + "/" + &channel)
        .body(serde_json::to_string(&msg).unwrap())
        .send()
        .await
    {
        "Successfully sent message!".to_owned()
    } else {
        format!("cannot send message to {receiver}").to_owned()
    }
}

// #################### Broadcasting functions ###########################

// Make RistrettoPoint to string
pub fn point_to_string(point: RistrettoPoint) -> String {
    let mut point_string = String::new();
    point_string.push_str(
        general_purpose::STANDARD_NO_PAD
            .encode(&point.compress().as_bytes())
            .as_str(),
    );
    point_string
}

// String to bytes
pub fn string_to_bytes(point: &str) -> Result<Vec<u8>, &'static str> {
    let decode_tmp = general_purpose::STANDARD_NO_PAD
        .decode(point.as_bytes())
        .unwrap();
    Ok(decode_tmp)
}

// Make string to RistrettoPoint
pub fn string_to_point(point: &str) -> Result<RistrettoPoint, &'static str> {
    let decode_tmp = string_to_bytes(point)?;
    if decode_tmp.len() != RISTRETTO_POINT_SIZE_IN_BYTES {
        return Err("string_to_point decode failed");
    }
    let point_value = match CompressedRistretto::from_slice(&decode_tmp).decompress() {
        Some(v) => v,
        None => return Err("string_to_point decompress CompressedRistretto failed"),
    };

    Ok(point_value)
}

/// Converts Scalar to an encoded string.
pub fn scalar_to_string(number: &Scalar) -> String {
    let mut number_string = String::new();
    number_string.push_str(
        general_purpose::STANDARD_NO_PAD
            .encode(&number.to_bytes())
            .as_str(),
    );
    number_string
}
/// Converts an encoded string to Scalar.
pub fn string_to_scalar(num: &str) -> Result<Scalar, &'static str> {
    let num_u8 = match string_to_bytes(num) {
        Ok(v) => v,
        Err(_) => {
            return Err("string_to_scalar failed");
        }
    };
    let get_num_u8 = to_bytes32_slice(&num_u8)?;
    let scalar_num = Scalar::from_bits(*get_num_u8);
    Ok(scalar_num)
}

fn to_bytes32_slice(barry: &[u8]) -> Result<&[u8; 32], &'static str> {
    let pop_u8 = match barry.try_into() {
        Ok(v) => v,
        Err(_) => {
            return Err("string_to_scalar failed");
        }
    };
    Ok(pop_u8)
}

// ########################### OLD HEADER ##################################

#[derive(Clone)]
pub struct PrivateKey {
    // ID of private key
    pub id: u32,
    // The actually private key
    key: Scalar,
}
impl PrivateKey {
    pub fn get_key(&self) -> Scalar {
        self.key
    }

    pub fn new(id: u32, key: Scalar) -> PrivateKey {
        PrivateKey { id, key }
    }
}

#[derive(Clone)]
pub struct PublicKey {
    // ID of private key
    pub id: u32,
    // The actually public key
    pub key: RistrettoPoint,
}
impl PublicKey {
    pub fn new(id: u32, key: RistrettoPoint) -> PublicKey {
        PublicKey { id, key }
    }
}

// Committee struct to hold all participants in the committee
#[derive(Clone)]
pub struct Committee {
    pub signers: HashMap<u32, RistrettoPoint>,
    pub tilde_y: RistrettoPoint,
}

// impl Committee {
//     pub fn new(signers: Vec<Signer>) -> Committee {
//         Committee {
//             signers,
//             public_key: RistrettoPoint::default(),
//         }
//     }

//     pub fn set_public_key(&mut self, key: RistrettoPoint) {
//         self.public_key = key;
//     }
// }

// Participant struct to hold possible signers of the message
// Each participant has a private key and a public key associated with it
// #[derive(Clone)]
// pub struct commitee_members {
//     pub id: u32,
//     pub private_key: PrivateKey,
//     pub public_key: PublicKey,
// }

// impl Signer {
//     pub fn new(id: u32, private_key: PrivateKey, public_key: PublicKey) -> Signer {
//         Signer {
//             id,
//             private_key,
//             public_key,
//         }
//     }
// }

// #################### Hash Coefficient ###########################
pub fn musig_coef(com: Committee, big_y: RistrettoPoint) -> Scalar {
    let mut hasher = Sha512::new();
    // Go through every participant in the committee.
    // Get the public key and add it to the hash
    for (_, big_y) in com.signers {
        hasher.update(big_y.compress().as_bytes());
    }
    // Add participant own public key
    hasher.update(big_y.compress().as_bytes());

    // Convert from hash in bytes to Scalar value
    let mut hash_in_bytes = [0u8; 64];
    hash_in_bytes.copy_from_slice(hasher.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&hash_in_bytes)
}

// #################### Hash Signature ###########################
pub fn hash_sig(tilde_y: RistrettoPoint, big_r: RistrettoPoint, m: String) -> Scalar {
    // Hashes the signature on the message
    let mut hasher = Sha512::new();

    // challange :=H_{sig}(\widetilde{Y},R,m)
    // hashing the for the signature challenge

    hasher.update(tilde_y.compress().as_bytes());
    hasher.update(big_r.compress().as_bytes());
    hasher.update(m.as_bytes());

    // convert the hash to a scalar to get the correct calulations
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);

    Scalar::from_bytes_mod_order_wide(&result_bytes)
}
// #################### Hash Nonce ###########################

pub fn hash_non(vehkey: RistrettoPoint, outs: Vec<RistrettoPoint>, m: String) -> Scalar {
    let mut hasher = Sha512::new();
    // hash $b:= H_{non}(\widetilde{Y},(R_1,...,R_v),m)$

    hasher.update(vehkey.compress().as_bytes());

    for out in outs.iter() {
        hasher.update(out.compress().as_bytes());
    }

    hasher.update(m.as_bytes());

    // convert the hash to a scalar to get the correct calulations
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);

    Scalar::from_bytes_mod_order_wide(&result_bytes)
}

// #################### Hash Key ###########################

pub fn hash_key(
    i: u32,
    context_string: String,
    ga: RistrettoPoint,
    big_r: RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    // hash $b:= H_{non}(\widetilde{Y},(R_1,...,R_v),m)$

    hasher.update(i.to_be_bytes());

    hasher.update(context_string.as_bytes());

    hasher.update(ga.compress().as_bytes());

    hasher.update(big_r.compress().as_bytes());

    // convert the hash to a scalar to get the correct calulations
    let result = hasher.finalize();
    let mut result_bytes = [0u8; 64];
    result_bytes.copy_from_slice(&result);

    Scalar::from_bytes_mod_order_wide(&result_bytes)
}

// #################### Helper functions ###########################

// Compute larange coefficient
// Used in key aggregation and signing
pub fn compute_lagrange_coefficient(committee: Committee, x0: u32) -> Scalar {
    let mut lagrange_coefficient = Scalar::one();

    // Standard lagrange coefficient calculation
    // https://en.wikipedia.org/wiki/Lagrange_polynomial
    for (&x, _) in committee.signers.iter() {
        if x != x0 {
            let calc = Scalar::from(x) * (Scalar::from(x) - Scalar::from(x0)).invert();
            lagrange_coefficient *= calc;
        }
    }
    lagrange_coefficient
}

// power function for Scalar, since Scalar does not have a pow function implemented
pub fn scalar_pow(base: Scalar, exp: u32) -> Scalar {
    let mut result = Scalar::one();
    for _ in 0..exp {
        result *= base;
    }
    result
}

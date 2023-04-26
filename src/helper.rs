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

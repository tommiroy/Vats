use serde::{Deserialize, Serialize};
use std::{clone, env};

use tokio::fs::File;
use tokio::io::AsyncReadExt;
use warp::*;


use super::helper::{get_identity, reqwest_read_cert};

#[derive(Serialize, Deserialize)]
struct Request {
    message: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Idmsg {
    identity: u32,
    text: String,
}

pub async fn run_client(ip: String) -> Result<(), reqwest::Error> {
    let server_ca_file_loc = "local_x509/ca/ca.crt";
    let cert = reqwest_read_cert(server_ca_file_loc.to_owned()).await;
    // let mut buf = Vec::new();
    // File::open(server_ca_file_loc)
    //     .await
    //     .unwrap()
    //     .read_to_end(&mut buf)
    //     .await
    //     .unwrap();
    // let cert = reqwest::Certificate::from_pem(&buf)?;

    // async fn get_identity() -> reqwest::Identity {
    //     let client_pem_file_loc = "src/client/client_0.pem";
    //     let mut buf = Vec::new();
    //     File::open(client_pem_file_loc)
    //         .await
    //         .unwrap()
    //         .read_to_end(&mut buf)
    //         .await
    //         .unwrap();
    //     reqwest::Identity::from_pem(&buf).unwrap()
    // }

    let identity = get_identity("local_x509/client/client_0.pem".to_owned()).await;

    let client = reqwest::Client::builder().use_rustls_tls();

    let client = client
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .identity(identity)
        .https_only(true)
        .build()?;

    let server_ip = "https://".to_owned() + &ip + "/";

    // let ras = send_message(&server_ip, &client, "route2", request2.clone()).await;
    let res = send_message(&server_ip, &client, "nonce", "keygen process".to_string()).await;
    println!("Received:");
    println!("Server responded with message: {:?}", res);
    // println!("Received:");
    // println!("Server responded with message: {:?}", ras);
    Ok(())
}

pub async fn send_message(
    server_ip: &str,
    client: &reqwest::Client,
    channel: &str,
    msg: String,
) -> reqwest::Response {
    client
        .post(server_ip.to_owned() + channel)
        .body(serde_json::to_string(&msg).unwrap())
        .send()
        .await
        .unwrap()
}

#![allow(dead_code)]
use super::util::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::runtime;

pub async fn run_cmd_center(identity: String, ca: String, addr: String, port: String) {
    // Build sending method for the server
    // The reason for this is so that this is not done everytime the server sends messages to other nodes.
    let _identity = get_identity(identity.clone()).await;
    let _ca = reqwest_read_cert(ca.clone()).await;
    // Build a client for message transmission
    // Force using TLS
    let _client = reqwest::Client::builder().use_rustls_tls();
    if let Ok(client) = _client
        // We use our own CA
        .tls_built_in_root_certs(false)
        // Receivers have to be verified by this CA
        .add_root_certificate(_ca)
        // Our identity verified by receivers
        .identity(_identity)
        // Force https
        .https_only(true)
        .build()
    {
        loop {
            println!("Command options:\n    1. keygen\n    2. sign\n    3. share update");
            println!("Your command: ");
            let stdin = BufReader::new(tokio::io::stdin());
            let mut lines = stdin.lines();
            if let Some(line) = lines.next_line().await.expect("No lines") {
                if let Ok(selection) = line.parse::<u8>() {
                    match selection {
                        1_u8 => {
                            let msg: Message = Message {
                                sender: "command_center".to_string(),
                                receiver: addr.clone(),
                                msg_type: MsgType::Keygen,
                                msg: vec!["Start share generation".to_owned()],
                            };
                            let ans = reqwest_send(
                                client.clone(),
                                addr.to_owned() + ":" + &port,
                                // "keygen".to_string(),
                                msg,
                            )
                            .await;
                            println!("Answer from central: {ans:?}");
                        }
                        2_u8 => {
                            println!("Message to sign: ");
                            let _stdin = BufReader::new(tokio::io::stdin());
                            let mut _lines = _stdin.lines();
                            if let Some(_line) = _lines.next_line().await.expect("No lines") {
                                let msg: Message = Message {
                                    sender: "command_center".to_string(),
                                    receiver: addr.clone(),
                                    msg_type: MsgType::Sign,
                                    msg: vec![_line],
                                };
                                let ans = reqwest_send(
                                    client.clone(),
                                    addr.to_owned() + ":" + &port,
                                    msg,
                                )
                                .await;
                                println!("Answer from central: {ans:?}");
                            }
                        }
                        3_u8 => {
                            println!("context: ");
                            let _stdin = BufReader::new(tokio::io::stdin());
                            let mut _lines = _stdin.lines();
                            if let Some(_line) = _lines.next_line().await.expect("No lines") {
                                let msg: Message = Message {
                                    sender: "command_center".to_string(),
                                    receiver: addr.clone(),
                                    msg_type: MsgType::KeyUpd,
                                    msg: vec![_line],
                                };
                                let ans = reqwest_send(
                                    client.clone(),
                                    addr.to_owned() + ":" + &port,
                                    msg,
                                )
                                .await;
                                println!("Answer from central: {ans:?}");
                            }
                        }
                        _ => {
                            println!("Don't care");
                        }
                    }
                }
            }
        }
    }
}

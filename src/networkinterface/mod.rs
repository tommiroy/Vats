/// ###################################################################
/// Argument options
/// Dont care about these
/// ###################################################################
use clap::{Args, Parser, Subcommand};
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct App {
    /// Name of the person to greet
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Server mode
    Server(ServerOption),
    /// Client mode
    Client(ClientOption),
}

#[derive(Args, Debug)]
struct ServerOption {
    // /// Certificates path
    // #[arg(long)]
    // cert: String,

    // /// Private key path
    // #[arg(long)]
    // key:String,
    /// Identity of the server: cert + key

    #[arg(short, long, default_value = "docker_x509/central/central.pem")]
    identity: String,

    /// Certificate Authority path
    #[arg(short, long, default_value = "docker_x509/ca/ca.crt")]
    ca: String,

    /// Server port
    #[arg(short, long, default_value = "3030")]
    port: String,
}

#[derive(Args, Debug)]
struct ClientOption {
    // /// Certificates path
    // #[arg(long)]
    // cert: String,

    // /// Private key path
    // #[arg(long)]
    // key:String,
    /// Identity of the server: cert + key

    #[arg(short, long, default_value = "docker_x509/ecu1/ecu1.pem")]
    identity: String,

    /// Certificate Authority path
    #[arg(short, long, default_value = "docker_x509/ca/ca.crt")]
    ca: String,

    // server address
    #[arg(long, default_value = "central")]
    central_addr: String,

    /// Server port
    #[arg(short, long, default_value = "3030")]
    port: String,
}

mod client;
mod helper;
mod server;

use client::run_client;
use helper::{Message, MsgType};
use server::Server;

use tokio::sync::mpsc::unbounded_channel;

// Testing only
// use serde::{Deserialize, Serialize};

/// ###################################################################
/// Main Function
/// ###################################################################

#[tokio::main]
async fn main() {
    let args = App::parse();

    match &args.mode {
        // Start as a server
        Mode::Server(ServerOption { identity, ca, port }) => {
            let (tx, mut rx) = unbounded_channel::<String>();
            let mut my_server = Server::new(
                identity.to_string(),
                ca.to_string(),
                port.to_string(),
                tx.clone(),
            )
            .await;

            // test for serializing and deserializing objects.
            // if let Ok(test_server_serialized) = serde_json::to_string(&my_server) {
            //     println!("{test_server_serialized}");
            //     let deserialized_server = serde_json::from_slice::<Server>(test_server_serialized.as_bytes());
            //     println!("{deserialized_server:?}")
            // } else {
            //     println!("Could not serialized the server");
            // }

            // Handle incoming message from tx channel
            loop {
                let Some(msg) = rx.recv().await else {
                    panic!("Server::main: received message is not a string");
                };

                if let Ok(msg) = serde_json::from_slice::<Message>(msg.as_bytes()) {
                    // Match the message type and handle accordingly
                    match msg.msg_type {
                        MsgType::Keygen => {
                            println!("KeyGen type: {}", msg.msg);
                            todo!("Add handler for keygen");
                        }
                        MsgType::Nonce => {
                            println!("Nonce type: {}", msg.msg);
                            todo!("Add nonce for keygen");
                        }
                        MsgType::Sign => {
                            println!("Sign type: {}", msg.msg);
                            todo!("Add sign for keygen");
                        }
                        MsgType::Update => {
                            println!("Update type: {}", msg.msg);
                            todo!("Add update for keygen");
                        }
                    }
                } else {
                    // Just for debugging
                    println!("Not of Message struct but hey: {msg:?}");
                }
            }
        }

        // Start as a client
        Mode::Client(ClientOption {
            identity,
            ca,
            central_addr,
            port,
        }) => {
            let _ = run_client(
                identity.to_string(),
                ca.to_string(),
                central_addr.to_owned() + ":" + port,
            )
            .await;
            // let _ = run_client("server:3030".to_string()).await;
            // println!("Arguments for Client: {option:?}");
        }
    }
}

// ###################################################################

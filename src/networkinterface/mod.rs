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

    /// Identity of the server: cert + key
    #[arg(short('i'), long, default_value = "docker_x509/central/central.pem")]
    identity: String,

    /// Certificate Authority path
    #[arg(short('c'), long, default_value = "docker_x509/ca/ca.crt")]
    ca: String,

    /// server address
    #[arg(short, long, default_value = "central")]
    addr: String,

    /// Server port
    #[arg(short('p'), long, default_value = "3030")]
    port: String,
}

#[derive(Args, Debug)]
struct ClientOption {

    #[arg(short('i'), long, default_value = "docker_x509/ecu1/ecu1.pem")]
    identity: String,

    /// Certificate Authority path
    #[arg(short('c'), long, default_value = "docker_x509/ca/ca.crt")]
    ca: String,

    /// server address
    #[arg(long("caddr"), default_value = "server")]
    central_addr: String,

    /// Central server port
    #[arg(long("cport"), default_value = "3030")]
    central_port: String,

    
    /// Server port
    #[arg(short('a'), long, default_value = "127.0.0.1")]
    addr: String,

    /// Server port
    #[arg(short('p'), long, default_value = "3031")]
    port: String,
}

mod client;
mod helper;
mod server;

// use client::run_client;
use client::Client;
use helper::{Message, MsgType};
use server::Server;

use tokio::sync::mpsc::unbounded_channel; 
// Testing only
// use serde::{Deserialize, Serialize};

/// ###################################################################
/// Main Function
/// ###################################################################

pub async fn network() {
    let args = App::parse();

    let (tx, mut rx) = unbounded_channel::<String>();
    match args.mode {
        // Start as a server
        Mode::Server(ServerOption { identity, ca, addr, port }) => {
            let mut my_server = Server::new(identity, ca, addr, port, tx).await;
            my_server.add_client("127.0.0.1:3031".to_string());
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
                            let test = my_server.send("client:3031".to_owned(), "keygen".to_owned(), msg.clone()).await;
                            println!("Status of sending message: \n {test:?}");
                            // todo!("Add handler for keygen");
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
        Mode::Client(ClientOption {identity, ca, central_addr, central_port, addr, port}) => {
            // let _ = run_client(
            //     identity.to_string(),
            //     ca.to_string(),
            //     central_addr.to_string(),
            //     port.to_string(),
            // )
            // .await;
            let my_client = Client::new(identity, ca, addr, port, central_addr, central_port, tx).await;
            let msg = Message {sender:"ecu1".to_string(), 
                                        receiver: "central".to_string(), 
                                        msg_type:MsgType::Keygen, 
                                        msg: "This is ecu1 test".to_string()};
            let res = my_client.send("keygen".to_owned(), msg).await;
            println!("{res:?}");

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
        // Mode::Client(ClientOption {identity, ca, central, addr, port}) => {
        //     let _ = run_client(
        //         identity.to_string(),
        //         ca.to_string(),
        //         central.to_string(),
        //         port.to_string(),
        //     )
        //     .await;
        // }

    }

}

// ###################################################################
// cargo run client -i /home/ab000668/thesis/implementation/Vats/local_x509/client/client.pem -c /home/ab000668/thesis/implementation/Vats/local_x509/ca/ca.crt -a 127.0.0.1 -p 3031 --caddr client --cport 3030
// cargo run server -i /home/ab000668/thesis/implementation/Vats/local_x509/server/server.pem -c /home/ab000668/thesis/implementation/Vats/local_x509/ca/ca.crt -a 127.0.0.1 -p 3030

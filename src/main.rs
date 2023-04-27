use std::thread::spawn;

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
    /// Command center
    Cmd(CmdCenterOption),
}

#[derive(Args, Debug)]
struct ServerOption {
    /// Identity of the server: cert + key
    #[arg(short('i'), long, default_value = "central")]
    id: String,

    /// Identity of the server: cert + key
    #[arg(short('e'), long, default_value = "docker_x509/central/central.pem")]
    identity: String,

    /// Certificate Authority path
    #[arg(short('c'), long, default_value = "docker_x509/ca/ca.crt")]
    ca: String,

    /// server address
    #[arg(short, long, default_value = "127.0.0.1")]
    addr: String,

    /// Server port
    #[arg(short('p'), long, default_value = "3030")]
    port: String,
}

#[derive(Args, Debug)]
struct ClientOption {
    #[arg(short('i'), long, default_value = "1")]
    id: u32,

    #[arg(short('e'), long, default_value = "docker_x509/ecu1/ecu1.pem")]
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

#[derive(Args, Debug)]
struct CmdCenterOption {
    #[arg(short('e'), long, default_value = "docker_x509/central/central.pem")]
    identity: String,

    /// Certificate Authority path
    #[arg(short('c'), long, default_value = "docker_x509/ca/ca.crt")]
    ca: String,

    /// server address
    #[arg(short, long, default_value = "central")]
    addr: String,

    /// Central server port
    #[arg(short, long, default_value = "3030")]
    port: String,
}

mod client;
mod cmd_center;
mod server;
mod signing;
mod util;
// use client::run_client;
use ::log::*;
use client::Client;
use cmd_center::run_cmd_center;
use server::Server;
use util::{point_to_string, scalar_to_string, Message, MsgType};

use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{sleep, Duration};
// Testing only
// use serde::{Deserialize, Serialize};

/// ###################################################################
/// Main Function
/// ###################################################################

#[tokio::main]
pub async fn main() {
    env_logger::init();
    let args = App::parse();

    let (tx, mut rx) = unbounded_channel::<String>();
    match args.mode {
        // ###################################################################
        // Start as a server
        // ###################################################################
        Mode::Server(ServerOption {
            id,
            identity,
            ca,
            addr,
            port,
        }) => {
            let mut my_server = Server::new(id, identity, ca, addr, port, tx).await;
            my_server.add_client("ecu1:3031".to_string());
            my_server.add_client("ecu2:3032".to_string());
            my_server.add_client("ecu3:3033".to_string());
            my_server.add_client("ecu4:3034".to_string());

            // Handle incoming message from tx channel
            sleep(Duration::from_millis(500)).await;

            // deal out keys

            loop {
                let Some(msg) = rx.recv().await else {
                    panic!("Server::main: received message is not a string");
                };

                if let Ok(msg) = serde_json::from_slice::<Message>(msg.as_bytes()) {
                    // Match the message type and handle accordingly
                    match msg.msg_type {
                        MsgType::Keygen => {
                            info!("Got keygen cmd!!!! RUN!");
                            my_server.clone().deal_shares(3, 4).await;

                            // println!(
                            //     "KeyGen type:\n Sender: {}\n Message: {:?}",
                            //     msg.sender, msg.msg
                            // );
                            // let res_broadcast =
                            //     my_server.broadcast("keygen".to_string(), msg).await;

                            // println!("Response from broadcast: \n {:?}", res_broadcast);
                            // let test = my_server.send("ecu1:3031".to_owned(), "keygen".to_owned(), msg.clone()).await;
                            // println!("Status of sending message: \n {test:?}");
                            // todo!("Add handler for keygen");
                        }
                        MsgType::Nonce => {
                            &my_server.nonce_handler(msg).await;
                        }
                        MsgType::Sign => {
                            if my_server.nonces.len() > 3 {
                                my_server.clone().sign_request(msg.msg[0].clone(), 3).await;
                            }
                        }
                        MsgType::Update => {
                            println!("Update type: {:?}", msg.msg);
                            todo!("Add update for keygen");
                        }
                        _ => {
                            println!("Placeholder")
                        }
                    }
                } else {
                    // Just for debugging
                    println!("Not of Message struct but hey: {msg:?}");
                }
            }
        }
        // ###################################################################
        // Start as a Client
        // ###################################################################
        Mode::Client(ClientOption {
            id,
            identity,
            ca,
            central_addr,
            central_port,
            addr,
            port,
        }) => {
            let my_client =
                Client::new(id, identity, ca, addr, port, central_addr, central_port, tx).await;
            // Testing purposes --------------------------------------------------
            // let msg = Message {sender:"ecu1".to_string(),
            //                             receiver: "central".to_string(),
            //                             msg_type:MsgType::Keygen,
            //                             msg: "This is ecu1 test".to_string()};
            // sleep(Duration::from_millis(500)).await;
            // let res = my_client.send("keygen".to_owned(), msg).await;
            // println!("{res:?}");
            // -------------------------------------------------------------------

            loop {
                let Some(msg) = rx.recv().await else {
                    panic!("Server::main: received message is not a string");
                };

                if let Ok(msg) = serde_json::from_slice::<Message>(msg.as_bytes()) {
                    // Match the message type and handle accordingly
                    match msg.msg_type {
                        MsgType::Keygen => {
                            // println!("KeyGen type: {:?}", msg.msg);
                            my_client.clone().init(msg.msg);
                            my_client.clone().nonce_generator(2).await;
                            // todo!("Add handler for keygen");
                        }
                        MsgType::Nonce => {
                            println!("Nonce type: {:?}", msg.msg);
                            // todo!("Add nonce for keygen");
                        }
                        MsgType::Sign => {
                            my_client.clone().sign_msg(msg.msg[0].clone()).await;
                            // println!("Sign type: {:?}", msg.msg);
                            // // todo!("Add sign for keygen");
                        }
                        MsgType::Update => {
                            println!("Update type: {:?}", msg.msg);
                            // todo!("Add update for keygen");
                        }
                    }
                } else {
                    // Just for debugging
                    println!("Not of Message struct but hey: {msg:?}");
                }
            }
        }
        Mode::Cmd(CmdCenterOption {
            identity,
            ca,
            addr,
            port,
        }) => {
            run_cmd_center(identity, ca, addr, port).await;
        }
    }
}

// ###################################################################
// cargo run client -i /home/ab000668/thesis/implementation/Vats/local_x509/client/client.pem -c /home/ab000668/thesis/implementation/Vats/local_x509/ca/ca.crt -a 127.0.0.1 -p 3031 --caddr client --cport 3030
// cargo run server -i /home/ab000668/thesis/implementation/Vats/local_x509/server/server.pem -c /home/ab000668/thesis/implementation/Vats/local_x509/ca/ca.crt -a 127.0.0.1 -p 3030

// Server handle methods
// User keydealer to generate keys and send each share to each participant

async fn server_handler(mut my_server: Server, mut rx: UnboundedReceiver<String>) {
    loop {
        let Some(msg) = rx.recv().await else {
            panic!("Server::main: received message is not a string");
        };

        if let Ok(msg) = serde_json::from_slice::<Message>(msg.as_bytes()) {
            // Match the message type and handle accordingly
            match msg.msg_type {
                MsgType::Keygen => {
                    println!(
                        "KeyGen type:\n Sender: {}\n Message: {:?}",
                        msg.sender, msg.msg
                    );
                    let res_broadcast = my_server.broadcast("keygen".to_string(), msg).await;
                    // println!("Response from broadcast: \n {:?}", res_broadcast);
                    // let test = my_server.send("ecu1:3031".to_owned(), "keygen".to_owned(), msg.clone()).await;
                    // println!("Status of sending message: \n {test:?}");
                    // todo!("Add handler for keygen");
                }
                MsgType::Nonce => {
                    &my_server.nonce_handler(msg).await;
                }
                MsgType::Sign => {
                    let mut input = String::new();
                    info!("Nonces: {:?}", my_server.clone().nonces.len());

                    if my_server.nonces.len() > 3 {
                        // take terminal input for message
                        println!("Enter message to sign: ");
                        std::io::stdin()
                            .read_line(&mut input)
                            .expect("Failed to read line");
                        my_server.clone().sign_request(input, 3).await;
                    }
                }
                MsgType::Update => {
                    println!("Update type: {:?}", msg.msg);
                    todo!("Add update for keygen");
                }
                _ => {
                    println!("Placeholder")
                }
            }
        } else {
            // Just for debugging
            println!("Not of Message struct but hey: {msg:?}");
        }
    }
}

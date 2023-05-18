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
    #[arg(short('i'), long, default_value = "0")]
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
use util::{Committee, Message, MsgType, compute_lagrange_coefficient};
use signing::keyUpd::update_share;

use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{sleep, Duration};
// Testing only
// use serde::{Deserialize, Serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use util::*;
use rand::rngs::OsRng;
/// ###################################################################
/// Main Function
/// ###################################################################


#[tokio::main]
pub async fn main() {
    signing::benchmark_execution_time_key_dealer(5, 10);
}

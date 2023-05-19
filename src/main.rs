use std::collections::HashMap;
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
use signing::keyAgg::key_agg;
use signing::signOn::sign_on;
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
use signing::*;

// #[tokio::main]
pub fn main() {
        

    
    scheme_tn(3, 4, 2);

    

}


fn scheme_tn (t:usize, n: usize, v:usize) {
    let (shares, pks, pk, sk, big_b) = key_dealer::dealer(t, n);

    let mut participants = HashMap::<u32, Client>::new();

    let mut pubkeys = HashMap::<u32, RistrettoPoint>::new();
    let _: Vec<_> = pks.iter().map(|pk| pubkeys.insert(pk.0, pk.1)).collect();

    for (id, share) in shares {
        let client: Client = Client {
            id: id,
            central: "".to_string(),
            _client: reqwest::Client::builder().use_rustls_tls().build().unwrap(),
            share: share,
            pubkey: pks[(id-1) as usize].1,
            pubkeys: pubkeys.clone(),
            vehkey: pk,
            big_r: Vec::<RistrettoPoint>::new(),
            rs: Vec::<Scalar>::new(),
            commitments: HashMap::<u32, Vec<RistrettoPoint>>::new(),
            commitments_msg: Vec::<Message>::new(),
            new_share_msg: Vec::<Message>::new(),
            keyupd_committee: Vec::<u32>::new(),
            context: "".to_owned(),

        };
        participants.insert(id, client);
    }


    // Create a committee for other methods
    let mut temp = HashMap::<u32, RistrettoPoint>::new();
    for (id, client) in participants.clone() {
        temp.insert(id, client.pubkey);
    }

    let committee = Committee::new(temp);

    // Everybody does signoff
    let mut outs = Vec::<Vec<RistrettoPoint>>::new();
    for (id, mut signer) in participants.clone() {
        (signer.big_r, signer.rs) = signOff::sign_off(v as u32);
        outs.push(signer.big_r.clone());
        participants.insert(id, signer);
    }

    // SA then does the first sign agg
    // This is the aggregated commitment used in signon
    let out = signAgg::sign_agg(outs, v as u32);

    // Signers create and store partial signatures
    let mut partsigns = HashMap::<u32, (RistrettoPoint, (Scalar, RistrettoPoint))>::new();
    let msg = "Message to sign".to_string();
    for (id, signer) in participants {
        let partsign_i = sign_on(signer.clone(), 
                                                                signer.rs.clone(), 
                                                                out.clone(), 
                                                                msg.clone(), 
                                                                committee.clone(), 
                                                                signer.big_r);

        partsigns.insert(id, partsign_i);
    }

    let tilde_r = tilde_r::calculate_tilde_r(committee.clone(), out, msg.clone());
    let mut z = Scalar::zero();
    let mut cheaters = Vec::<u32>::new();

    for id in committee.signers.keys().clone() {
        let &(tilde_rx, (zx, big_rx)) = partsigns.get(id).unwrap();
        if tilde_r != tilde_rx {
            cheaters.push(*id);
        }
        let &big_yx = committee.signers.get(id).unwrap();
        let rho_x = musig_coef(committee.clone(), big_yx);
        let lambda_x = compute_lagrange_coefficient(committee.clone(), *id);
        let c_x = hash_sig(pk, tilde_rx, msg.clone());
        let ver = &RISTRETTO_BASEPOINT_TABLE * &partsigns.get(id).unwrap().1.0;
        if ver != big_rx + big_yx * (c_x * (rho_x + lambda_x)) {
            cheaters.push(*id);
        } else {
            z += zx;
        }
    }
    
    
    verification::ver(
        msg.clone(),
        pk,
        (tilde_r, z),
        committee,
    );

}
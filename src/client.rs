#![allow(dead_code)]
#![warn(clippy::too_many_arguments)]

use crate::signing::header::Signer;

use super::helper::*;
// use crate::signing::share_ver::share_ver;
use ::log::*;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use std::{collections::HashMap, net::SocketAddr};
use tokio::sync::mpsc::UnboundedSender;
use vats::signing::share_ver::share_ver;
use vats::signing::signOff::sign_off;
use warp::*;
#[derive(Clone, Debug)]
pub struct Client {
    // Name of the node
    pub id: u32,
    // // Certificate and key of this server
    // identity: String,
    // // CA of other nodes
    // ca: String,
    // // server address
    // addr: String,
    // // Port that this server runs on
    // port: String,

    // Address of central server
    central: String,
    // clients:    HashMap<String, String>,
    _client: reqwest::Client,
    // Secret share
    share: Scalar,
    // Client public keys
    pubkey: RistrettoPoint,

    // Public keys: <ID, pubkey>
    pubkeys: Vec<(u32, RistrettoPoint)>,
    // Vehicle pubkey
    vehkey: RistrettoPoint,
    // r:s
    rs: Vec<Scalar>,
}
impl Client {
    pub async fn new(
        id: u32,
        identity: String,
        ca: String,
        addr: String,
        port: String,
        central_addr: String,
        central_port: String,
        tx: UnboundedSender<String>,
    ) -> Client {
        let _addr = addr.clone();
        let _port = port.clone();
        let _ca = ca.clone();
        let _identity = identity.clone();

        tokio::spawn(async move {
            _serve(_identity, _ca, _addr, _port, tx).await;
        });
        // Build sending method for the server
        // The reason for this is so that this is not done everytime the server sends messages to other nodes.
        let _identity = get_identity(identity.clone()).await;
        let _ca = reqwest_read_cert(ca.clone()).await;
        // Build a client for message transmission
        // Force using TLS
        let _client = reqwest::Client::builder().use_rustls_tls();
        if let Ok(_client) = _client
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
            // Only return Server instance _client is built.
            let central = central_addr.to_owned() + ":" + &central_port;
            // Create and return an instance of Client
            Self {
                id,
                central,
                _client,
                share: Scalar::zero(),
                pubkey: RistrettoPoint::identity(),
                pubkeys: Vec::<(u32, RistrettoPoint)>::new(),
                vehkey: RistrettoPoint::identity(),
                rs: Vec::<Scalar>::new(),
            }
        } else {
            panic!("Cant build _client");
        }
    }
    // Have not tested
    pub async fn send(&self, channel: String, msg: Message) -> String {
        reqwest_send(self._client.clone(), self.central.clone(), channel, msg).await
    }

    // When received a keygen message from server then verify the share and store it together with pubkeys and group key
    pub fn init(&mut self, mut setup_msg: Vec<String>) {
        // Commitments from dealer
        let index = setup_msg
            .iter()
            .position(|x| x == "big_bs")
            .expect("Client-init: Cannot split big_bs");
        let big_bs = setup_msg.split_off(index + 1);
        setup_msg.pop();

        // Individual public keys
        let index = setup_msg
            .iter()
            .position(|x| x == "pks")
            .expect("Client-init: Cannot split pks");
        let pks = setup_msg.split_off(index + 1);
        setup_msg.pop();

        // Get vehicle's public key
        let vehkey = setup_msg.pop().expect("Cannot pop group public key");
        // Get ECU's secret share
        let share = setup_msg.pop().expect("Cannot pop share");

        self.share = string_to_scalar(&share).unwrap();
        self.vehkey = string_to_point(&vehkey).unwrap();
        for pk in pks {
            let (id, pk) = pk.split_once(':').unwrap();
            let id = id.parse::<u32>().unwrap();
            let pk = string_to_point(pk).unwrap();
            self.pubkeys.push((id, pk));
        }
        let mut ver_list = Vec::<RistrettoPoint>::new();
        for big_b in big_bs {
            let big_b = string_to_point(&big_b).unwrap();
            ver_list.push(big_b);
        }

        //   Vec<(u32, RistrettoPoint)>, my_id: u32, share: Scalar, t: usize, n: usize,
        (self.share, self.pubkey) = share_ver(ver_list, self.id, self.share, 3, 4);
    }

    // Generate nonce for a signing session
    pub async fn nonce_generator(&mut self, v: u32) {
        info!("Sent nonces to server");
        let mut big_rs = Vec::<RistrettoPoint>::new();

        (big_rs, self.rs) = sign_off(v);

        let nonce_list = Message {
            sender: self.id.clone().to_string(),
            receiver: "central".to_string(),
            msg_type: MsgType::Nonce,
            msg: big_rs.iter().map(|big_r| point_to_string(*big_r)).collect(),
        };

        self.send("nonce".to_string(), nonce_list).await;
    }

    pub asyn

    //SA -> ecu -> ge mig nya nonces
    //ECU får meddelande -> generate nonce -> SA -> SA

    //SA -> choose committee -> plockar ut big_r -> generate out -> skicka till ECUs samt meddelande, committee
}

async fn _serve(
    identity: String,
    ca: String,
    addr: String,
    port: String,
    tx: UnboundedSender<String>,
) {
    // Wrap the transmission channel into a Filter so that it can be included into warp_routes
    // Technicality thing
    let warp_tx = warp::any().map(move || tx.clone());

    // Create routes for different algorithms
    let warp_routes = warp::post()
        // Match with multiple paths since their messages are handled similarly
        .and(
            warp::path("keygen")
                .or(warp::path("nonce"))
                .unify()
                .or(warp::path("sign"))
                .unify()
                .or(warp::path("update"))
                .unify(),
        )
        // Match with json since the message is a serialized struct
        .and(warp::body::json())
        // Just to include transmission channel
        // This is to send the received messages back to the main thread
        .and(warp_tx.clone())
        // Handle the receieved messages
        .map(|msg: String, warp_tx: UnboundedSender<String>| {
            // Handle the message received by the server
            // Just send it back to main thread
            if let Err(e) = warp_tx.send(msg.clone()) {
                panic!("Cant relay message back to main thread!. Error: {e}");
            } else {
                // Honestly no need. Just debugging
                // println!("Sent a message back!");
            }
            // Reply back to the sender.
            // Reply the original message for debugging just for now. Otherwise, just reply Ok(200 code)
            warp::reply::json(&msg)
        });
    // Serve the connection.
    // Will run in forever loop. There is a way to gracefully shutdown this. But nah for now.
    if let Ok(socket) = (addr.to_owned() + ":" + &port).parse::<SocketAddr>() {
        warp::serve(warp_routes)
            .tls()
            .key_path(identity.clone())
            .cert_path(identity.clone())
            .client_auth_required_path(ca.clone())
            .run(socket)
            .await;
    } else {
        panic!("Invalid server address or port")
    }
}

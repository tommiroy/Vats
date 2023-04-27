#![allow(dead_code)]
use super::util::*;
use crate::signing::key_dealer::dealer;
use crate::signing::signAgg::sign_agg;

use ::log::info;
use flume::r#async;
// use flume::r#async;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::prelude::*;
use serde_json::to_string;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;
use warp::*;
// #[derive(Clone, Deserialize, Debug, Serialize)]
#[derive(Clone, Debug)]
pub struct Server {
    pub id: String,
    // Certificate and key of this server
    // identity: String,
    // // CA of other nodes
    // ca: String,
    // // server address
    // addr: String,
    // // Port that this server runs on
    // port: String,
    // List of clients/nodes/neighbours
    pub clients: Vec<String>,
    // clients:    HashMap<String, String>,
    _client: reqwest::Client,
    // List of nonces from signoff
    pub nonces: HashMap<u32, Vec<RistrettoPoint>>,
}

impl Server {
    pub async fn new(
        id: String,
        identity: String,
        ca: String,
        addr: String,
        port: String,
        tx: UnboundedSender<String>,
    ) -> Server {
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
            Self {
                id,
                // identity,
                // ca,
                // addr,
                // port,
                clients: Vec::<String>::new(),
                _client,
                nonces: HashMap::<u32, Vec<RistrettoPoint>>::new(),
            }
        } else {
            panic!("Cant build _client");
        }
    }
    // Have not tested
    pub fn add_client(&mut self, addr: String) {
        self.clients.push(addr);
    }
    // tested
    pub async fn send(&self, receiver: String, channel: String, msg: Message) -> String {
        reqwest_send(self._client.clone(), receiver, channel, msg).await
    }
    // Have not tested
    // Broadcast a message to all nodes in clients
    pub async fn broadcast(&self, channel: String, msg: Message) {
        for node in self.clients.clone() {
            let res = self.send(node.clone(), channel.clone(), msg.clone()).await;
            // println!("Sending message to {}: \n Response: {:?}", node, res);
        }
    }

    pub async fn deal_shares(self, t: usize, n: usize) {
        // Generate keys
        let (sks, pks, group_pk, _, big_b) = dealer(t, n);
        for (id, node) in self.clients.clone().into_iter().enumerate() {
            // Send each share to each participant
            // node.send()
            let secret_key = scalar_to_string(&sks[id].1);
            let vehicle_key = point_to_string(group_pk);

            //creating vector of keys to be able to send both keys in one message
            let mut keys = vec![];
            keys.push(secret_key);
            keys.push(vehicle_key);

            keys.push("pks".to_string());

            let _: Vec<_> = pks
                .iter()
                .map(|pk| keys.push(format!("{}:{}", pk.0, point_to_string(pk.1))))
                .collect();

            keys.push("big_bs".to_string());

            let _: Vec<_> = big_b
                .iter()
                .map(|b| keys.push(point_to_string(*b)))
                .collect();

            // message consturciton
            let keygen_msg = Message {
                sender: self.id.clone(),
                receiver: node.clone(),
                msg_type: MsgType::Keygen,
                msg: keys,
            };

            info!("Sending message: {:?}", keygen_msg.msg);

            self.send(node, "keygen".to_owned(), keygen_msg).await;
        }
    }

    pub async fn nonce_handler(&mut self, msg: Message) {
        // println!("Nonce handler: {:?}", msg);
        // println!("Nonce handler: {:?}", msg.msg);
        info!("Recieved Nonces: {:?}", msg.msg);
        self.nonces.insert(
            msg.sender.parse::<u32>().unwrap(),
            msg.msg
                .iter()
                .map(|x| {
                    string_to_point(x)
                        .expect("Server-nonce_handler: Couldnt not convert to RistrettoPoint")
                })
                .collect(),
        );
    }
    pub async fn sign_msg(self, message: String, t: usize) {
        let mut committee: Vec<u32> = self.nonces.clone().into_keys().collect();
        let mut rng = rand::thread_rng();
        committee.shuffle(&mut rng);
        let committee: Vec<u32> = committee.into_iter().take(t).collect();

        let mut outs = Vec::<Vec<RistrettoPoint>>::new();
        // let temp_nonces: HashMap<u32, Vec<RistrettoPoint>> = self.nonces.clone();

        for id in committee.clone() {
            outs.push(
                self.nonces
                    .get(&id)
                    .expect("Server-sig_msg: Cannot find nonce")
                    .to_vec(),
            );
        }

        let _out = sign_agg(outs, 2);
        // Put out and message into a message a string vector
        let mut out = Vec::<String>::new();
        out.push(message.clone());
        let _: Vec<_> = _out.iter().map(|r| out.push(point_to_string(*r))).collect();

        for i in committee.clone().into_iter() {
            let sign_req = Message {
                sender: self.id.clone(),
                receiver: i.to_string(),
                msg_type: MsgType::Keygen,
                msg: out.clone(),
            };

            info!(
                "Signature request to committee:{:?}\n
                Message to sign: {:?}",
                committee, sign_req.msg
            );

            self.send(i.to_string(), "sign_req".to_owned(), sign_req)
                .await;
        }
    }
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
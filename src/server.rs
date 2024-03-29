#![allow(dead_code)]
use super::signing::signAgg2::sign_agg2;
use super::util::*;
use crate::signing::key_dealer::dealer;
use crate::signing::signAgg::sign_agg;
// use crate::signing::tilde_r::calculate_tilde_r;
// use crate::signing::*;

use ::log::*;

// use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

// use super::util::*;
use rand::prelude::*;
// use serde_json::to_string;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;
use warp::*;

// #[derive(Clone, Deserialize, Debug, Serialize)]
#[derive(Clone, Debug)]
pub struct Server {
    pub id: String,
    // List of clients/nodes/neighbours
    pub clients: HashMap<u32, String>,
    // clients:    HashMap<String, String>,
    _client: reqwest::Client,
    // Vehicle Key
    pub vehkey: RistrettoPoint,
    // Public keys: <ID, pubkey>
    pub pubkeys: HashMap<u32, RistrettoPoint>,
    // List of nonces from signoff
    pub nonces: HashMap<u32, Vec<RistrettoPoint>>,
    // indivdual bigR from each signer
    // pub bigRx: HashMap<u32, Vec<RistrettoPoint>>,
    // Signing committee members
    pub committee: HashMap<u32, RistrettoPoint>,
    // Partial signatures
    pub partial_sigs: HashMap<u32, (RistrettoPoint, (RistrettoPoint, Scalar))>,
    // Aggregated nonces
    pub out: Vec<RistrettoPoint>,
    // Current Message
    pub m: String,
    // TEST
    pub test: HashMap<u32, Scalar>
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
                clients: HashMap::<u32,String>::new(),
                _client,
                pubkeys: HashMap::<u32, RistrettoPoint>::new(),
                vehkey: RistrettoPoint::default(),
                nonces: HashMap::<u32, Vec<RistrettoPoint>>::new(),
                committee: HashMap::<u32, RistrettoPoint>::new(),
                // bigRx: HashMap::<u32, Vec<RistrettoPoint>>::new(),
                partial_sigs: HashMap::<u32, (RistrettoPoint, (RistrettoPoint, Scalar))>::new(),
                out: Vec::<RistrettoPoint>::new(),
                m: String::new(),
                // TEST
                test: HashMap::<u32, Scalar>::new(),
            }
        } else {
            panic!("Cant build _client");
        }
    }
    // Have not tested
    pub fn add_client(&mut self,id :u32 , addr: String) {
        self.clients.insert(id, addr);
    }
    // tested
    pub async fn send(&self, receiver: String, msg: Message) -> String {
        reqwest_send(self._client.clone(), receiver, msg).await
        // reqwest_send(self._client.clone(), receiver, channel, msg).await

    }
    // Have not tested
    // Broadcast a message to all nodes in clients
    pub async fn broadcast(&self, msg: Message) {
        for node in self.clients.clone() {
            // println!("broadcast: sender: {}", msg.sender);
            // println!("broadcast: msg_type: {:?}", msg.msg_type);
            // if node.0 != msg.sender.parse::<u32>().unwrap() {
            let res = self.send(node.1.clone(), msg.clone()).await;
            // }
            // println!("Sending message to {}: \n Response: {:?}", node, res);
        }
    }

    //
    //--------------------------------------------------------------------------------
    // Dealer that send each client their share
    //
    pub async fn deal_shares(&mut self, t: usize, n: usize) {
        // Generate keys
        let (sks, pks, group_pk, _, big_b) = dealer(t, n);

        // Add vehcile keys to the server
        self.vehkey = group_pk;

        pks.iter().for_each(|pk| {
            self.pubkeys.insert(pk.0, pk.1);
        });

        for (id, node) in self.clients.clone() {
            // Send each share to each participant
            // node.send()
            let secret_key = scalar_to_string(&sks[(id-1) as usize].1);
            let vehicle_key = point_to_string(self.vehkey);

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
                sender: self.id.to_string(),
                receiver: node.clone(),
                msg_type: MsgType::Keygen,
                msg: keys,
            };

            // info!("Sending message: {:?}", keygen_msg.msg);

            self.send(node, keygen_msg).await;
        }
    }

    //
    //--------------------------------------------------------------------------------
    // handles recieved nonces from the clients
    //
    pub async fn nonce_handler(&mut self, msg: Message) {
        // info!("Recieved Nonces: {:?}", msg.msg);
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

    //
    //--------------------------------------------------------------------------------
    // Signrequest to clients for a certain message
    //

    pub async fn sign_request(&mut self, message: String, t: usize) {
        self.m = message.clone();
        // select a random committee
        let mut committee: Vec<u32> = self.nonces.clone().into_keys().collect();
        let mut rng = rand::thread_rng();
        committee.shuffle(&mut rng);
        let committee: Vec<u32> = committee.into_iter().take(t).collect();

        let mut outs = Vec::<Vec<RistrettoPoint>>::new();

        // Store the committee
        for i in committee.clone() {
            if self.pubkeys.contains_key(&i) {
                self.committee.insert(i, self.pubkeys[&i]);
            }
        }
        // Store the nonces
        for id in committee.clone() {
            outs.push(
                self.nonces
                    .get(&id)
                    .expect("Server-sig_msg: Cannot find nonce")
                    .to_vec(),
            );
        }
        // Aggregate the nonces
        self.out = sign_agg(outs, 2);
        // Put out and message into a message a string vector
        let mut msg = Vec::<String>::new();
        let _committee = committee
            .iter()
            .map(|x: &u32| x.to_string() + ",")
            .collect::<String>();

        // construct message
        msg.push(_committee.trim_end_matches(',').to_string());
        msg.push(message.clone());
        let _: Vec<_> = self
            .out
            .iter()
            .map(|r| msg.push(point_to_string(*r)))
            .collect();
        for i in committee.clone().into_iter() {
            let sign_req = Message {
                sender: self.id.to_string(),
                receiver: i.to_string(),
                msg_type: MsgType::Sign,
                msg: msg.clone(),
            };

            info!(
                "Signature request to committee:{:?}\n
                Message to sign: {:?}",
                committee, sign_req.msg
            );
            // send signature request to clients
            self.send(
                self.clients.get(&i).expect("server: Cannot find client").to_string(),
                // "sign".to_owned(),
                sign_req,
            )
            .await;
        }
    }
    //
    //--------------------------------------------------------------------------------
    // handles recieved signatures from the clients
    //
    pub async fn sign_aggregate(
        &mut self,
        msg: Message,
        t: usize,
    ) -> Result<(RistrettoPoint, Scalar), Vec<u32>> {
        let tilde_rx = string_to_point(&msg.msg.get(0).unwrap().clone()).unwrap();
        let zx = string_to_scalar(&msg.msg.get(1).unwrap().clone()).unwrap();
        let big_rx = string_to_point(&msg.msg.get(2).unwrap().clone()).unwrap();

        self.partial_sigs.insert(
            msg.sender
                .parse::<u32>()
                .expect("server-sig_aggregate: cannot convert id"),
            (tilde_rx, (big_rx, zx)),
        );

        if self.partial_sigs.len() >= t {
            let signature: Result<(RistrettoPoint, Scalar), Vec<u32>> = sign_agg2(self);
            // match signature.clone() {
            //     Ok(sign) => {
            //         println!("SIGNATURE VERIFIED!!!!");
            //     }
            //     Err(cheaters) => {
            //         println!("CHEATERS!!!!!");
            //     }
            // }
            signature
        } else {
            Err(Vec::<u32>::new())
        }
    }

    pub fn clear(&mut self) {
        self.nonces = HashMap::<u32, Vec<RistrettoPoint>>::new();
        self.committee = HashMap::<u32, RistrettoPoint>::new();
        // self.bigRx = HashMap::<u32, Vec<RistrettoPoint>>::new();
        self.partial_sigs = HashMap::<u32, (RistrettoPoint, (RistrettoPoint, Scalar))>::new();
        // out: Vec::<RistrettoPoint>::new(),
        self.m = String::new();
    }

    pub async fn request_nonces(&self) {
        self.broadcast(
            // "nonce".to_owned(),
            Message {
                sender: "0".to_string(),
                receiver: "all".to_string(),
                msg_type: MsgType::Nonce,
                msg: vec!["".to_string()],
            },
        )
        .await;
    }

    pub fn new_pubkey_handler(&mut self, msg: Message) {
        let k = msg.sender.parse::<u32>().unwrap();
        let v = string_to_point(&msg.msg[0].clone()).unwrap();
        self.pubkeys.insert(k, v).unwrap();
        info!("New pubkey receieved from {k}: {}", point_to_string(v));
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
        // .and(
            // warp::path("keygen")
            //     .or(warp::path("nonce"))
            //     .unify()
            //     .or(warp::path("sign"))
            //     .unify()
            //     .or(warp::path("signagg"))
            //     .unify()
            //     .or(warp::path("update"))
            //     .unify(),
            
            // )
            // Match with json since the message is a serialized struct
        .and(warp::any())
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

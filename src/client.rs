#![allow(dead_code)]
#![warn(clippy::too_many_arguments)]

use crate::signing::signOn::sign_on;

use super::util::*;
// use crate::signing::share_ver::share_ver;
use super::signing::share_ver::share_ver;
use super::signing::signOff::sign_off;
use super::signing::keyUpd::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use ::log::*;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;
use warp::*;

#[derive(Clone, Debug)]
pub struct Client {
    // Name of the node
    pub id: u32,
    // Address of central server
    central: String,
    // clients:    HashMap<String, String>,
    _client: reqwest::Client,
    // Secret share
    share: Scalar,
    // Client public keys
    pub pubkey: RistrettoPoint,
    // Public keys: <ID, pubkey>
    pub pubkeys: HashMap<u32, RistrettoPoint>,
    // Vehicle pubkey
    pub vehkey: RistrettoPoint,
    // big r:s
    big_r: Vec<RistrettoPoint>,
    // nonces
    rs: Vec<Scalar>,
    // ------------ Key Updating --------------
    // Commitments in key updating
    pub commitments: HashMap::<u32, Vec<RistrettoPoint>>,
    pub commitments_msg: Vec<Message>,
    pub new_share_msg: Vec<Message>,
    // Key updating committee
    pub keyupd_committee: Vec<u32>,
    // Context 
    pub context: String,

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
                pubkeys: HashMap::<u32, RistrettoPoint>::new(),
                vehkey: RistrettoPoint::identity(),
                big_r: Vec::<RistrettoPoint>::new(),
                rs: Vec::<Scalar>::new(),
                commitments: HashMap::<u32, Vec<RistrettoPoint>>::new(),
                commitments_msg: Vec::<Message>::new(),
                new_share_msg: Vec::<Message>::new(),
                keyupd_committee: Vec::<u32>::new(),
                context: "".to_owned(),
            }
        } else {
            panic!("Cant build _client");
        }
    }
    pub fn get_share(&self) -> Scalar {
        self.share
    }

    pub fn set_share(&mut self, share: Scalar) {
        self.share = share;
    }
    // Have not tested
    pub async fn send(&self, channel: String, msg: Message) -> String {
        reqwest_send(self._client.clone(), self.central.clone(), msg).await
        // reqwest_send(self._client.clone(), self.central.clone(), channel, msg).await

    }
    //
    //--------------------------------------------------------------------------------
    // When received a keygen message from server then verify the share and store it together with pubkeys and group key
    //

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
            self.pubkeys.insert(id, pk);
        }
        let mut ver_list = Vec::<RistrettoPoint>::new();
        for big_b in big_bs {
            let big_b = string_to_point(&big_b).unwrap();
            ver_list.push(big_b);
        }

        self.pubkey = self.pubkeys.get(&self.id).unwrap().clone();
        //   Vec<(u32, RistrettoPoint)>, my_id: u32, share: Scalar, t: usize, n: usize,
        (self.share, self.vehkey) = share_ver(ver_list, self.id, self.share);
    }

    //
    //--------------------------------------------------------------------------------
    // generate nonces and send to server
    //
    pub async fn nonce_generator(&mut self, v: u32) {
        // info!("Sent nonces to server");

        (self.big_r, self.rs) = sign_off(v);

        let nonce_list = Message {
            sender: self.id.clone().to_string(),
            receiver: "0".to_string(),
            msg_type: MsgType::Nonce,
            msg: self
                .big_r
                .iter()
                .map(|big_r| point_to_string(*big_r))
                .collect(),
        };

        self.send("nonce".to_string(), nonce_list).await;
    }
    //
    //--------------------------------------------------------------------------------
    // Sign a message
    //
    pub async fn sign_msg(&self, msg: Vec<String>) {
        let com_ids: Vec<u32> = msg[0]
            .split(',')
            .map(|id| id.parse::<u32>().unwrap())
            .collect::<Vec<u32>>();
        // match these commitee ids with the keys in publickeys hasmap and create a committee
        info!("Committee to sign: {:?}", com_ids.clone());
        let mut com = HashMap::<u32, RistrettoPoint>::new();
        for i in com_ids {
            if self.pubkeys.contains_key(&i) {
                com.insert(i, self.pubkeys[&i]);
            }
        }
        let committee = Committee::new(com);
        let msg_to_sign = &msg[1];

        let out = msg[2..]
            .iter()
            .map(|x| string_to_point(x).unwrap())
            .collect::<Vec<RistrettoPoint>>();
        let (big_r, (z, big_ri)) = sign_on(
            self.clone(),
            self.clone().rs,
            out,
            msg_to_sign.to_owned(),
            committee,
            self.big_r.clone(),
        );
        // info!(
        //     "Individual signature: {:?}",
        //     (point_to_string(big_r), scalar_to_string(&z))
        // );
        let sig_msg = Message {
            sender: self.id.to_string(),
            receiver: "0".to_string(),
            msg_type: MsgType::SignAgg,
            msg: vec![
                point_to_string(big_r),
                scalar_to_string(&z),
                point_to_string(big_ri),
            ],
        };
        self.send("signagg".to_string(), sig_msg).await;
    }

    pub fn commitment_handler(&mut self, msg: Message) {
        self.commitments_msg.push(msg);
        // check that all committtee members ar inside the commitments
        if self.commitments_msg.len() == self.keyupd_committee.len() {
            for msg in self.commitments_msg.clone(){
                let big_rx: RistrettoPoint = string_to_point(&msg.msg[0]).expect("client-commitment_handler: Cannot convert to point");
                let zx: Scalar = string_to_scalar(&msg.msg[1]).expect("client-commitment_handler: Cannot convert to scalar");
                let mut big_cx: Vec<RistrettoPoint> = Vec::<RistrettoPoint>::new();
                let _: Vec<_> = msg.msg[2..].iter().map(|big_a| big_cx.push(string_to_point(big_a).expect("client-commitment_handler: Cannot convert to point"))).collect();
                self.commitments.insert(msg.sender.parse::<u32>().unwrap(), big_cx.clone());

                // check that all committtee members ar inside the commitments
                let big_a = big_cx.clone()[0];
                // warn!("Commitments from all committee members received. {:?}", self.commitments.keys());
                if verify_sigma(self, (big_rx, zx), big_a, self.context.clone(), msg.sender.parse::<u32>().unwrap()) {
                    // info!("New commitment from {} added.",msg.sender.parse::<u32>().unwrap());
                } else {
                    info!("Commitment Verification from {} failed.", msg.sender.parse::<u32>().unwrap());
                    self.commitments.remove(&msg.sender.parse::<u32>().unwrap());
                }
            }
            self.commitments_msg = Vec::<Message>::new();
        }
    }   


    pub async fn new_share_handler(&mut self, msg: Message) {
        self.new_share_msg.push(msg);
        if self.new_share_msg.len() == self.keyupd_committee.len() {
            let mut si = Scalar::zero();
            // let mut my_new_share = self.get_share();

            for msg in self.new_share_msg.clone() {
                let f_xi = string_to_scalar(&msg.msg[0]).expect("client-new_share_handler: cannot parse share from string");
                let x = msg.sender.parse::<u32>().expect("client-new_share_handler: Cannot parse sender's id");
                info!("New share received from {}: {}", x, msg.msg[0]);                
                // Upon receiving (i, fx(i)), Pi verifies their shares by calculating:
                if verify_new_share(self, x, f_xi) {
                    let lambda_x = compute_lagrange_coefficient(Committee::new(self.pubkeys.clone()), x);
                    si += f_xi * lambda_x;
                } else {
                    info!("verification of new share failed!");
                }
            }
            // update_pubkeys(self);
            
            self.set_share(si);
            // Then Pi stores si securely, and deletes each fx(i).
            self.new_share_msg = Vec::<Message>::new(); 
            info!("Client: New share updated to: {:?}", scalar_to_string(&self.get_share()));
            // Calculate and public key:
            self.pubkey = &RISTRETTO_BASEPOINT_TABLE*&self.get_share();
            self.pubkeys.insert(self.id, self.pubkey);

            self.send("channel".to_string(), Message { sender: self.id.to_string(), receiver: "()".to_string(), msg_type: MsgType::KeyUpdNewPubkey, msg: vec![point_to_string(self.pubkey)] }).await;

        }
    }

    pub fn new_pubkey_handler(&mut self, msg: Message) {
        let k = msg.sender.parse::<u32>().unwrap();
        let v = string_to_point(&msg.msg[0].clone()).unwrap();
        self.pubkeys.insert(k, v).unwrap();
        info!("New pubkey receieved from {k}: {}", point_to_string(v));
    }
   

}
//
//--------------------------------------------------------------------------------
// listener for the client
//
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
            //     .or(warp::path("update"))
            //     .unify(),
        // )
        .and(warp::any())
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

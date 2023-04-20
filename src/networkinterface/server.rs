#![allow(dead_code)]
use tokio::sync::mpsc::UnboundedSender;
use warp::*;
use std::net::SocketAddr;
use super::helper::{get_identity, reqwest_read_cert, Message};

// #[derive(Clone, Deserialize, Debug, Serialize)]
#[derive(Clone, Debug)]
pub struct Server {
    // Certificate and key of this server
    identity: String,
    // CA of other nodes
    ca: String,
    // server address
    addr: String,
    // Port that this server runs on
    port: String,
    // List of clients/nodes/neighbours
    clients: Vec<String>,
    // clients:    HashMap<String, String>,
    _client: reqwest::Client,
}

impl Server {
    pub async fn new(
        identity: String,
        ca: String,
        addr:String, 
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
            Self {identity, ca, addr, port, clients: Vec::<String>::new(), _client}
        } else {
            panic!("Cant build _client");
        }
    }
    // Have not tested
    pub fn add_client(&mut self, addr: String) {
        self.clients.push(addr);
    }
    // Have not tested
    pub async fn send(&self, receiver: String, channel: String, msg: Message) -> reqwest::Response {
        // Serialize the message
        let msg = serde_json::to_string(&msg).expect("Cant serialize this message");
        // Send it!
        self._client
            .post("https://".to_owned() + &receiver + "/"+ &channel)
            .body(msg)
            .send()
            .await
            .unwrap()
    }
    // Have not tested
    // Broadcast a message to all nodes in clients
    pub async fn broadcast(&self, channel: String, msg: Message) {
        for node in self.clients.clone() {
            self.send(node, channel.clone(), msg.clone()).await;
        }
    }
}

async fn _serve(identity: String, ca: String, addr:String, port: String, tx: UnboundedSender<String>) {
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
                println!("Sent a message back!");
            }
            // Reply back to the sender.
            // Reply the original message for debugging just for now. Otherwise, just reply Ok(200 code)
            warp::reply::json(&msg)
        });
    // Serve the connection.
    // Will run in forever loop. There is a way to gracefully shutdown this. But nah for now.
    if let Ok(socket) = (addr.to_owned()+":"+ &port).parse::<SocketAddr>() {
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

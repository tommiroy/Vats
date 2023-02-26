use flume::{unbounded, Receiver, Sender};
use log::{debug, warn};

mod acast;
pub mod server;

/// initalizes acast and listening server. Must be called first!
pub async fn init(port: u16, network: Vec<String>) {
    debug!("Initializing networking interface");
    let (tx_to_server, rx_to_acast_server): (Sender<String>, Receiver<String>) = unbounded();

    let _ = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(server::server(port))
    });

    acast::init(rx_to_acast_server, network).await;

    server::add_to_pubsub(acast::get_id(), tx_to_server)
        .await
        .ok();
}

/// Cast onto the network. note that [init] must be called first!
/// Tag is associated with received channel which may be acquired by [get_receive_channel].
///
/// A message sent to a TAG or socket which does not exist will simply be dropped.
pub async fn cast(tag: String, msg: String) {
    acast::cast(tag, msg).await;
}

/// Sends a message to a socket. note that [init] must be called first!
/// Tag is associated with received channel which may be acquired by [get_receive_channel].
///
/// A message sent to a TAG or socket which does not exist will simply be dropped.
pub async fn send(tag: String, msg: String, socket: String) {
    server::send(tag, msg, socket).await.ok();
    // tokio::spawn(server::send(tag, msg, socket));
}

/// Register a tag to listen to. Returns a receive channel which all such tagged messages
/// will be deliver to. See [send] and [cast]. [init] must be called first!
pub async fn get_receive_channel(id: String) -> Receiver<String> {
    let (tx_to_server, rx_to_client): (Sender<String>, Receiver<String>) = unbounded();
    server::add_to_pubsub(id.clone(), tx_to_server).await.ok();
    warn!("Creating a server of {id}");
    rx_to_client
}

pub fn get_size() -> i32 {
    server::get_total()
}

pub fn get_total_messages() -> i32 {
    server::get_total_messages()
}

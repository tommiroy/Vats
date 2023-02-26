use bincode;
use flume::Sender;
use lazy_static::lazy_static;
use log::{debug, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Serialize, Clone, Deserialize, PartialEq, Eq)]
struct NetworkInterfaceMessage {
    body: String,
    tag: String,
}

lazy_static! {
    static ref PUBSUBS: Mutex<HashMap<String, Sender<String>>> = {
        let h = HashMap::new();
        Mutex::new(h)
    };
    static ref TOTAL_SIZE: AtomicI32 = AtomicI32::new(0);
    static ref TOTAL_MESSAGES: AtomicI32 = AtomicI32::new(0);
}

pub async fn add_to_pubsub(tag: String, channel: Sender<String>) -> Result<(), String> {
    let mut e = PUBSUBS.lock().await;
    e.insert(tag, channel);
    Ok(())
}

pub async fn server(port: u16) -> Result<(), &'static str> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await;
    match listener {
        Err(_) => {
            warn!("Server failed on bind!");
            panic!("")
        }
        Ok(listener) => {
            info!("Server up and running on http://{}", addr);
            loop {
                let stream = listener.accept().await;
                trace!("Accepted a connection");
                match stream {
                    Err(e) => {
                        warn!("Failed to accept client on {e}");
                        continue;
                    }
                    Ok(e) => {
                        let (stream, _) = e;
                        warn!("SERVER: Received a message");
                        let mut reader = tokio::io::BufReader::new(stream);
                        let mut buf = vec![];

                        warn!("2");
                        if let Err(e) = reader.read_to_end(&mut buf).await {
                            warn!("Error receiving tcp stream: {e:?}");
                        } else {
                            warn!("3");
                            tokio::spawn(handle_inc_request(buf));
                        }
                    }
                }
            }
        }
    };
}

async fn handle_inc_request(str: Vec<u8>) {
    warn!("inside handle inc request");
    TOTAL_SIZE.fetch_add(str.len() as i32, Relaxed);
    TOTAL_MESSAGES.fetch_add(1, Relaxed);
    let nim: Result<NetworkInterfaceMessage, _> = bincode::deserialize(&str);

    warn!("inside handle inc request");
    match nim {
        Ok(e) => {
            let hmap = PUBSUBS.lock().await;
            if let Some(chn) = hmap.get(&e.tag) {
                debug!(
                    "received a message and queueing to channel: {:?} \n {:?}",
                    e.tag, e.body
                );
                chn.send(e.body.clone()).ok();
            } else {
                debug!("dropped incoming message since no channel is matching id tag");
            }
        }
        Err(e) => warn!(
            "Hard failure while deserializing with error: {}",
            e.to_string()
        ),
    }
}

pub async fn deliver(tag: String, msg: String) {
    let e = PUBSUBS.lock().await;
    if let Some(chn) = e.get(&tag) {
        chn.send(msg).ok();
    }
}

pub async fn send<'l>(
    tag: String,
    body: String,
    socket: String,
) -> std::result::Result<(), std::io::Error> {
    let x = bincode::serialize(&NetworkInterfaceMessage { body, tag }).unwrap();
    warn!("tcp connect commencing");
    let stream = TcpStream::connect(socket.clone()).await;
    warn!("tcp connect complete");
    match stream {
        Ok(mut e) => {
            warn!("Message got sent");
            e.write_all(&x).await.ok();
            Ok(())
        }
        Err(e) => {
            let e2 = e.to_string();
            warn!("Error sending to socket \"{socket}\" with error message {e2}");
            Err(e)
        }
    }
}

pub fn get_total() -> i32 {
    TOTAL_SIZE.load(Relaxed)
}

pub fn get_total_messages() -> i32 {
    TOTAL_MESSAGES.load(Relaxed)
}

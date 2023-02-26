use flume::Receiver;
use futures::lock::Mutex;
use futures::stream::FuturesUnordered;
use lazy_static::lazy_static;
use log::{debug, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};
use uuid::Uuid;

use super::server;

/// The type of an ACast message can have 3 types. Refer to [paper] section A-Cast.
///
/// [paper]: http://www.cs.tau.ac.il/~canetti/materials/cr93.ps
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
enum ACastType {
    Msg,
    Echo,
    Ready,
}

/// Internal enum for keeping track of at what stage a given message is.
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
enum ACastMessageStatus {
    Delivered,
    Msged,
    Echoed,
    None,
    ReadyFst,
    ReadySnd,
}

/// Internal encapsulating type for an ACastMessage.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ACastMessage {
    id: String,
    message: String,
    typ: ACastType,
    tag: String,
}

/// Internal struct for keeping track of the number of each message status that has been received.
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
struct MessageCount {
    echo: usize,
    ready: usize,
}

type MessageSetType = Mutex<HashMap<String, (ACastMessageStatus, HashMap<String, MessageCount>)>>;

lazy_static! {
    // Set of all messages, needs garbagecollecting(!)
    static ref MESSAGE_SET: MessageSetType = {
        let h = HashMap::new();
        Mutex::new(h)
    };

    // The set of all sockets on the cast network
    static ref ENVIRONMENT: Mutex<Vec<String>> = Mutex::new(vec![]);

    // tag of local module
    static ref TAG: String = "acast".to_string();

    // Semaphore used for spawning the server without async sleep hardcoding
    static ref RUNNING: tokio::sync::Semaphore = tokio::sync::Semaphore::new(0);
}

/// Initializes the server
pub async fn init(inc_messages: Receiver<String>, network: Vec<String>) {
    // add all sockets to local environment
    for elem in network {
        (ENVIRONMENT.lock().await).push(elem);
    }

    // spawns the server which unclocks the "RUNNING" lock once initialized
    tokio::spawn(server(inc_messages));

    RUNNING.acquire().await.ok();
}

/// Returns module ID for this module.
pub fn get_id() -> String {
    TAG.clone()
}

/// Casts a message onto the network with n/3 - 1 tolerance.
///
/// Note that message is not delivered upon await. Message is merely
/// initialized.
///
/// For receival of message, listen to incoming messages with the same tag.
///
/// public wrapper for [send_message].

pub async fn cast(tag: String, message: String) {
    let id = Uuid::new_v4().to_string();
    let msg = ACastMessage {
        id: id.clone(),
        message,
        typ: ACastType::Msg,
        tag,
    };
    send_message(msg).await;
}

/// Runs when server is initialized and listens to receive channel.
///
/// Will release the lock in [init] of the module.
async fn server(rx: Receiver<String>) -> Result<(), &'static str> {
    // unlocks the barrier in initialization. (see init)
    RUNNING.add_permits(1);

    // forever loop for accepting incoming acast-messages
    loop {
        let stream = rx.recv_async().await;
        trace!("SERVER: Accepted a connection");
        match stream {
            Err(e) => {
                warn!("SERVER: Failed to accept client on {e}");
                continue;
            }
            Ok(e) => {
                trace!("SERVER: Received a message");

                match try_parse(e) {
                    Ok(e) => handle_acast_message(e).await,
                    Err(e) => warn!("Failed to parse ACast message {e:?}"),
                }
            }
        }
    }
}

/// Attempts to parse the body of a request into an ACastMessage
///
/// #Err
/// Upon error, a string from the parser will be embedded
///
/// #Res
/// A parsed ACastMessage

fn try_parse(req: String) -> Result<ACastMessage, String> {
    serde_json::from_str::<ACastMessage>(&req).map_err(|e| e.to_string())
}

/// Handles incoming messages tagged with the `msg` tag. Ends by casting `echo`.
///
/// Refer to [Fast asynchronous Byzantine agreement with optimal resilience][paper], A-cast step 2
///
/// [paper]: http://www.cs.tau.ac.il/~canetti/materials/cr93.ps

async fn handle_acast_message(msg: ACastMessage) {
    Uuid::from_str(&msg.id)
        .map_err(|_| {
            warn!("SERVER: Failed to parse id of message, discarding msg: \n{msg:?}");
        })
        .ok();
    let typ: ACastType = msg.typ;
    trace!("SERVER: Received a message of type {typ:?}");
    match typ {
        ACastType::Msg => handle_msg(msg).await,
        ACastType::Echo => handle_echo(msg).await,
        ACastType::Ready => handle_ready(msg).await,
    }
}

/// Handles incoming messages tagged with the [ACastType::Msg] tag. Ends by casting a message with type [ACastType::Echo].
///
/// Refer to [Fast asynchronous Byzantine agreement with optimal resilience][paper], A-cast step 2
///
/// [paper]: http://www.cs.tau.ac.il/~canetti/materials/cr93.ps

async fn handle_msg(msg: ACastMessage) {
    let id = String::from(&msg.id);

    // errors here should be handled
    let mut x = MESSAGE_SET.lock().await;
    let echo_msg = ACastMessage {
        id: id.clone(),
        message: msg.message.clone(),
        typ: ACastType::Echo,
        tag: msg.tag.clone(),
    };
    debug!("SERVER: recieved an Echo with ID {id}");
    let msgctr = MessageCount { echo: 0, ready: 0 };
    let mut inner_hash = HashMap::new();
    inner_hash.insert(msg.message, msgctr);
    x.insert(id, (ACastMessageStatus::Echoed, inner_hash));

    send_message(echo_msg).await;
}

/// Handles incoming messages tagged with the [ACastType::Echo] tag. Will send
/// out [ACastType::Ready] when `n-t` [ACastType::Echo] has been recieved.
///
/// Refer to [Fast asynchronous Byzantine agreement with optimal resilience][paper], A-cast step 3
///
/// [paper]: http://www.cs.tau.ac.il/~canetti/materials/cr93.ps
async fn handle_echo(msg: ACastMessage) {
    let id = String::from(&msg.id);

    let n = ENVIRONMENT.lock().await.len();
    let t = f32::ceil(n as f32 / 3.0) as usize - 1;

    let n_minus_t = n - t;
    // errors here should be handled
    let mut shared_hashmap = MESSAGE_SET.lock().await;
    match shared_hashmap.get(&id) {
        None => {
            trace!(
                "SERVER: Received an Echo of a message not previously received as Msg of id {id}"
            );
            let msgctr = MessageCount { echo: 1, ready: 0 };
            let mut inner_hash = HashMap::new();

            if 1 >= n_minus_t {
                // proceed to step 3
                debug!("SERVER: Proceeding to step 3 for message id {id} with Echo count 1");
                let readyfst_msg = ACastMessage {
                    id: id.clone(),
                    message: msg.message.clone(),
                    typ: ACastType::Ready,
                    tag: msg.tag.clone(),
                };
                inner_hash.insert(msg.message, msgctr);
                shared_hashmap.insert(id.clone(), (ACastMessageStatus::ReadyFst, inner_hash));
                send_message(readyfst_msg).await;
            } else {
                // remain in step 2
                debug!("SERVER: Remaining in step 2 for message id {id} with Echo count 1");
                inner_hash.insert(msg.message, msgctr);
                shared_hashmap.insert(id, (ACastMessageStatus::None, inner_hash));
            }
        }
        Some((last_action, messagecount)) => {
            match messagecount.get(&msg.message) {
                None => {
                    trace!("SERVER: Received a new permutation of previously received message of id {id}");
                    let new_entry = MessageCount { echo: 1, ready: 0 };
                    let mut inner_hash = HashMap::new();
                    // Echoes >= n - t  and we haven't sent Ready yet.
                    if 1 >= n_minus_t && *last_action == ACastMessageStatus::Echoed {
                        debug!("SERVER: Proceeding to step 3 for permutated message with id {id} with Echo count 1 ");
                        inner_hash.insert(msg.message.clone(), new_entry);
                        shared_hashmap
                            .insert(id.clone(), (ACastMessageStatus::ReadyFst, inner_hash));

                        let readyfst_msg = ACastMessage {
                            id: id.clone(),
                            message: msg.message.clone(),
                            typ: ACastType::Ready,
                            tag: msg.tag.clone(),
                        };
                        send_message(readyfst_msg).await;
                    } else {
                        debug!("SERVER: Remaining in step 2 for permutated message with id {id} with Echo count 1");
                        let mut inner_hash = HashMap::new();
                        inner_hash.insert(msg.message.clone(), new_entry);
                        shared_hashmap.insert(id.clone(), (ACastMessageStatus::None, inner_hash));
                    }
                }
                Some(entry) => {
                    let typ = msg.typ;
                    trace!("SERVER: Received an echo of a message with id {id},\n previous action for this id was \
                                {typ:?}");
                    let echoes = entry.echo + 1;
                    let mut new_entry = entry.to_owned();
                    new_entry.echo = echoes;

                    let mut new_messagecount = messagecount.clone();
                    new_messagecount.insert(msg.message.clone(), new_entry);
                    // echoes >= n - t and we havent sent Ready yet.
                    if echoes >= n_minus_t && *last_action == ACastMessageStatus::Echoed {
                        debug!("SERVER: Proceeding to step 3 for message with id {id} with Echo count {echoes}");
                        shared_hashmap
                            .insert(id.clone(), (ACastMessageStatus::ReadyFst, new_messagecount));

                        let mut readyfst_msg = msg.clone();
                        readyfst_msg.typ = ACastType::Ready;
                        send_message(readyfst_msg).await;
                    } else {
                        debug!("SERVER: Remaining in step 2 for message with id {id} with Echo count {echoes}");
                        let last_action = *last_action;
                        shared_hashmap.insert(id.clone(), (last_action, new_messagecount));
                    }
                }
            }
        }
    }
}

/// Handles incoming messages tagged with the [ACastType::Ready] tag. Will send out [ACastType::Ready]
/// when `t + 1` Ready has been recieved. Will deliver when `2t + 1` [ACastType::Ready] has been received.
///
/// Refer to [Fast asynchronous Byzantine agreement with optimal resilience][paper], A-cast step 4 and 5
///
/// [paper]: http://www.cs.tau.ac.il/~canetti/materials/cr93.ps
async fn handle_ready(msg: ACastMessage) {
    let id = String::from(&msg.id);

    let n = ENVIRONMENT.lock().await.len();
    let t = f32::ceil(n as f32 / 3.0) as usize - 1;
    let t_plus_1 = t + 1;
    let twot_plus_1 = 2 * t + 1;

    let mut shared_hashmap = MESSAGE_SET.lock().await;
    match shared_hashmap.get(&id) {
        None => {
            let msgctr = MessageCount { echo: 0, ready: 1 };
            let mut message_count_hashmap = HashMap::new();
            message_count_hashmap.insert(msg.message, msgctr);
            shared_hashmap.insert(id, (ACastMessageStatus::None, message_count_hashmap));
        }
        Some((ACastMessageStatus::Delivered, _)) => (),
        Some((last_action, message_count_hashmap)) => {
            match message_count_hashmap.get(&msg.message) {
                None => {
                    // found an entry for the ID but message is permutated
                    let mut last_action = *last_action;

                    let msgctr = MessageCount { echo: 0, ready: 1 };
                    let mut message_count_hashmap = message_count_hashmap.clone();
                    message_count_hashmap.insert(msg.message.clone(), msgctr);

                    if 1 >= t_plus_1 && last_action == ACastMessageStatus::ReadyFst {
                        last_action = ACastMessageStatus::ReadySnd;
                        send_message(msg).await;
                    }
                    shared_hashmap.insert(id, (last_action, message_count_hashmap));
                }
                Some(e) => {
                    let mut messagecount = *e;
                    if e.ready + 1 >= twot_plus_1 && *last_action == ACastMessageStatus::ReadySnd {
                        let id = msg.id;
                        messagecount.ready += 1;
                        let debug_num_readys = messagecount.ready;
                        debug!(
                            "SERVER: delivered message with id {id} after {debug_num_readys} ready"
                        );
                        let mut inner_hashmap = message_count_hashmap.clone();
                        inner_hashmap.insert(msg.message.clone(), messagecount);
                        shared_hashmap
                            .insert(id.clone(), (ACastMessageStatus::Delivered, inner_hashmap));
                        info!("SERVER: delivered message with id {id}");
                        server::deliver(msg.tag, msg.message).await;
                        // deliver!
                    } else if e.ready + 1 >= t_plus_1
                        && *last_action == ACastMessageStatus::ReadyFst
                    {
                        messagecount.ready += 1;
                        let debug_num_readys = messagecount.ready;
                        debug!("SERVER: Sending second ready message with id {id} after {debug_num_readys} ready");
                        let mut inner_hashmap = message_count_hashmap.clone();
                        inner_hashmap.insert(msg.message.clone(), messagecount);
                        shared_hashmap
                            .insert(id.clone(), (ACastMessageStatus::ReadySnd, inner_hashmap));
                        send_message(msg).await;
                    } else {
                        messagecount.ready += 1;
                        let mut inner_hashmap = message_count_hashmap.clone();
                        inner_hashmap.insert(msg.message.clone(), messagecount);
                        let last_action = *last_action;
                        shared_hashmap.insert(id.clone(), (last_action, inner_hashmap));
                        send_message(msg).await;
                    }
                }
            }
        }
    }
}

/// Cast a message onto the network. Note that message is not delivered on await!
async fn send_message(message: ACastMessage) {
    let body_str = serde_json::to_string(&message).unwrap();
    let futs = ENVIRONMENT
        .lock()
        .await
        .clone()
        .into_iter()
        .map(|neighbour: String| server::send(TAG.clone(), body_str.clone(), neighbour));

    debug!("CLIENT: Cast features started");
    let mut successful = 0;

    for f in futs {
        if f.await.is_ok() {
            successful += 1;
        }
    }

    if successful >= 1 {
        debug!("CLIENT: Casting successful");
    } else {
        warn!("CLIENT: Casting unsuccessful");
    }
}

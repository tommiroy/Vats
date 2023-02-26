/*
Main file is solely for testing.
*/

use dealer::bl;
use tokio::time::{Duration, Instant};
//mod networkinterface;
//use core::num::dec2flt::parse;
use std::{collections::HashMap, env, io::Write};
mod dealer;
#[tokio::main]
async fn main() {
//    // initialize logging
//    env_logger::init();
//    let args: Vec<String> = env::args().collect();
//    // println!("{}", args[1]);
//    let port = args[1].parse::<u16>().unwrap();
//    let network = vec![
//        "0.0.0.0:3000".to_string(),
//        "0.0.0.0:3001".to_string(),
//        "0.0.0.0:3002".to_string(),
//        "0.0.0.0:3003".to_string(),
//    ];
//
//    // init the network will yield delivery channel from acast
//    networkinterface::init(port, network.clone()).await;

    bl();
    
//    // spawn a recieve channel on ba
//    let rx = networkinterface::get_receive_channel("ba".to_string()).await;
//    // acast a message on channel ba
//    //networkinterface::cast("ba".to_string(), "Hello from ba".to_string()).await;
//    // print the message received
//    //println!("Received: {}", rx.recv_async().await.unwrap());
}
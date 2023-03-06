#![allow(dead_code)]
#![allow(unused_variables)]
/*
Main file is solely for testing.
*/
use curve25519_dalek::scalar::Scalar;

use header::compute_lagrange_coeff;
use signing::bl;
use tokio::time::{Duration, Instant};
use vats::dealer;
//mod networkinterface;
//use core::num::dec2flt::parse;
use std::{collections::HashMap, env, io::Write};
mod signing;
//#[tokio::main]

use crate::header::Signer;
mod header;

use crate::testground::test_ristretto;
mod testground;

fn main() {
    bl();
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

    // bl();

    //    // spawn a recieve channel on ba
    //    let rx = networkinterface::get_receive_channel("ba".to_string()).await;
    //    // acast a message on channel ba
    //    //networkinterface::cast("ba".to_string(), "Hello from ba".to_string()).await;
    //    // print the message received
    //    //println!("Received: {}", rx.recv_async().await.unwrap());,

    // test_to_scalar();
    // let result:u32 =  1/(-1)*3/1*4/2;
    // assert_eq!(compute_lagrange_coeff(&2, &vec!{1,2,3,4}), Scalar::from(result));

    // test_ristretto();
}

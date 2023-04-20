#![allow(dead_code)]
#![allow(unused_variables)]
/*
Main file is solely for testing.
*/
use curve25519_dalek::scalar::Scalar;

// use header::compute_lagrange_coeff;
use signing::bl;
use tokio::time::{Duration, Instant};
use vats::dealer;
//mod networkinterface;
//use core::num::dec2flt::parse;
use std::{collections::HashMap, env, io::Write};
mod signing;
//#[tokio::main]

mod networkinterface;

#[tokio::main]
async fn main() {
    // test_signing();
    //bl();
    // run tokio thread with a client
    networkinterface::network().await;
}

// Co-authored-by: tommiroy <tommiroy@users.noreply.github.com>

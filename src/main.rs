#![allow(dead_code)]
#![allow(unused_variables)]
/*
Main file is solely for testing.
*/
use curve25519_dalek::scalar::Scalar;

// use header::compute_lagrange_coeff;
use signing::thresholdsignature;
use std::env;
use tokio::time::{Duration, Instant};
use vats::dealer;
//mod networkinterface;
//use core::num::dec2flt::parse;
mod signing;
//#[tokio::main]

use pbr::ProgressBar;

use crate::testground::test_ristretto;
mod testground;

mod test_signing;
use crate::test_signing::*;

fn main() {
    // test_signing();
    // take arg
    let args: Vec<String> = env::args().collect();
    let times = args[1].parse::<usize>().unwrap();
    let n = args[2].parse::<usize>().unwrap();
    let t = args[3].parse::<usize>().unwrap();

    let mut failed = 0;
    let mut bar = ProgressBar::new(times as u64);
    bar.format("╢▌▌░╟");

    let mut progress = 0u32;
    for i in 0..times {
        bar.inc();
        if thresholdsignature(t, n + 1, 2) {
            // println!("Signature verified");
        } else {
            failed += 1;
            // println!("Signature failed");
        }
    }
    bar.finish_print("done");
    println!("Failed {} times out of {} times.", failed, times);
}

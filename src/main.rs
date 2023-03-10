#![allow(dead_code)]
#![allow(unused_variables)]
/*
Main file is solely for testing.
*/
use curve25519_dalek::scalar::Scalar;

// use header::compute_lagrange_coeff;
use signing::bl;
use vats::dealer;
//mod networkinterface;
//use core::num::dec2flt::parse;
mod signing;
//#[tokio::main]

mod testground;

mod test_signing;
use crate::test_signing::*;

fn main() {
    // test_signing();
    bl();
}

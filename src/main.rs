#![allow(dead_code)]
#![allow(unused_variables)]
/*
Main file is solely for testing.
*/

// use header::compute_lagrange_coeff;
mod networkinterface;
//use core::num::dec2flt::parse;
mod signing;

#[tokio::main]
async fn main() {
    // test_signing();
    //bl();
    // run tokio thread with a client
    networkinterface::network().await;
}

// Co-authored-by: tommiroy <tommiroy@users.noreply.github.com>

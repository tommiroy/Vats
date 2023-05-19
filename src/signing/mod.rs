// use curve25519_dalek::scalar::Scalar;
// use rand::prelude::*;

pub mod keyAgg;
pub mod keyUpd;
pub mod key_dealer;
pub mod share_ver;
pub mod signAgg;
pub mod signAgg2;
pub mod signOff;
pub mod signOn;
pub mod tilde_r;
pub mod verification;

use std::time::Instant;
use std::fs::File;
use std::io::{Error, Write};

use std::collections::HashMap;

// pub mod test_key_dealer;
// use criterion::{black_box, criterion_group, criterion_main, Criterion};


use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use super::util::*;

pub fn benchmark_execution_time_key_dealer(t : usize, n : usize) {


    // let path = "benchmark_keygen.txt";
    // let mut output = File::create(path).expect("Cannot find the file");

    // let ts = vec![34, 67, 67, 134, 101, 201, 167, 334];
    // let ns = vec![100, 100, 200, 200, 300, 300, 500, 500];

    // for (&t,&n) in ts.iter().zip(ns.iter()) {
    //     writeln!(output, "----------- {},{} ---------", t, n);
    //     let before = Instant::now();
    //     key_dealer::dealer(t as usize,n as usize);
    //     writeln!(output, "{},{},{:.2?}", t,n, before.elapsed());
    // }


    // Create shares

    let (shares, pks, pk, sk, big_b) = key_dealer::dealer(t, n);
    
    // let mut participants = HashMap::<u32, Signer>::new();
    // for (id, share) in shares {
    //     participants.insert(id, Signer::new(id, share, pks[(id-1) as usize].1));
    // }




}


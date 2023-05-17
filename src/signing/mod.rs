// use curve25519_dalek::scalar::Scalar;
// use rand::prelude::*;

pub mod keyAgg;
pub mod keyUpd;
pub mod key_dealer;
pub mod muSigCoef;
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


use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn benchmark_execution_time_key_dealer(t : usize, n : usize) {
    let path = "benchmark_keygen_t=0.5n.txt";
    let mut output = File::create(path).expect("Cannot find the file");

    // let ts = vec![5, 10, 50, 100, 200, 500, 2000];
    // let ns = vec![5, 10, 50, 100, 200, 500, 2000];

    // for t in ts.clone() {
    //     writeln!(output, "----------- t = {} ---------", t);
    //     for n in ns.clone() {
    //         if n < t {
    //             continue;
    //         }
    //         let before = Instant::now();
    //         key_dealer::dealer(t,n);
    //         writeln!(output, "{},{},{:.2?}", t,n, before.elapsed());
    //     }
        
    // }

    // let (mut t,mut n) = (5,200);

    // while t<200 {
    //     let before = Instant::now();
    //     key_dealer::dealer(t,n);
    //     writeln!(output, "{},{},{:.2?}", t,n, before.elapsed().as_millis());
    //     t += 10;
    // }


    // let (mut t,mut n) = (5,5);

    // while n<200 {
    //     let before = Instant::now();
    //     key_dealer::dealer(t,n);
    //     writeln!(output, "{},{},{:.2?}", t,n, before.elapsed().as_millis());
    //     n += 10;
    // }

    
    // let (mut t,mut n) = (5,5);

    // while n<200 {
    //     t = (n/2) as usize;
    //     let before = Instant::now();
    //     key_dealer::dealer(t,n);
    //     writeln!(output, "{},{},{:.2?}", t,n, before.elapsed().as_millis());
    //     n += 10;

    // }
    
}
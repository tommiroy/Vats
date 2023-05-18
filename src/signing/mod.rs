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


// pub mod test_key_dealer;
// use criterion::{black_box, criterion_group, criterion_main, Criterion};


use super::util::*;

pub fn benchmark_execution_time_key_dealer(t : usize, n : usize) {
    // // let poly: Vec<u32> = vec![1,2,3];
    // // let poly: Vec<Scalar> = poly.iter().map(|x| Scalar::from(*x)).collect();

    // // print!("{:?}",eval_poly(0, poly));

    // let mut rng: OsRng = OsRng;

    // // Dealer samples t random values t-1 a   ----> t = 3
    // let mut a: Vec<Scalar> = Vec::with_capacity(t);
    // for _ in 0..t {
    //     a.push(Scalar::random(&mut rng));
    // }

    // // let poly: Vec<u32> = vec![1,2,3];
    // // let a : Vec<Scalar> = poly.iter().map(|x| Scalar::from(*x)).collect();



    // let mut shares = Vec::with_capacity(t);
    // for i in 1..n + 1 {
    //     let mut share = Scalar::zero();
    //     for j in 0..a.len() {
    //         share += a[j] * scalar_pow(Scalar::from(i as u32), j as u32);
    //     }
    //     shares.push((i as u32, share));
    // }
    
    // let mut new_shares = Vec::<(u32, Scalar)>::with_capacity(t);
    // for i in 1..n + 1 {
    //     let new_share = eval_poly(i as u32, a.clone());
    //     new_shares.push((i as u32, new_share));
    // }
    
    // // assert_eq!(new_shares.len(), shares.len(), "not same length()");
    
    // for (&share, &new_share) in shares.iter().zip(new_shares.iter()){
    //     // assert_eq!(share, new_share, "########## NOT EQUAL ########");
    //     // println!("OLD: {:?}", share);
    //     // println!("NEW: {:?}", new_share);

    //     assert_eq!(scalar_to_string(&share.1), scalar_to_string(&new_share.1), "########## NOT EQUAL ########");
    // }


    let path = "benchmark_keygen.txt";
    let mut output = File::create(path).expect("Cannot find the file");

    let ts = vec![34, 67, 67, 134, 101, 201, 167, 334];
    let ns = vec![100, 100, 200, 200, 300, 300, 500, 500];

    for (&t,&n) in ts.iter().zip(ns.iter()) {
        writeln!(output, "----------- {},{} ---------", t, n);
        let before = Instant::now();
        key_dealer::dealer(t as usize,n as usize);
        writeln!(output, "{},{},{:.2?}", t,n, before.elapsed());
    }

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


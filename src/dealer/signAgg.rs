use std::iter::Sum;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use super::signOff;

pub fn signAgg(outs: Vec<Vec<RistrettoPoint>>, v: u32) -> Vec<RistrettoPoint> {
    let mut out_temp = Vec::with_capacity(v as usize);
    for i in 0..v {
        let mut bigRs = Vec::<RistrettoPoint>::new();
        for j in 0..outs.len() {
            bigRs.push(outs[j][i as usize]);
        }
        out_temp.push(bigRs);
    }

    let mut out = Vec::with_capacity(v as usize);
    for i in out_temp {
        let tmp = i.iter().sum::<RistrettoPoint>();
        out.push(tmp);
    }
    out
}

// a1 a2 = out1
// b1 b2 = out2
// c1 c2 = out3
// d1 d2 = out4
// e1 e2 = out5

// R1 = a1 + b1 + c1 + d1 + e1
// R2 = a2 + b2 + c2 + d2 + e2

// Test function
pub fn test_signagg() {
    let (out1, _) = signOff(2);
    let (out2, _) = signOff(2);
    let (out3, _) = signOff(2);
    let (out4, _) = signOff(2);
    let (out5, _) = signOff(2);

    let outs = vec![out1, out2, out3, out4, out5];

    let out = signAgg(outs, 2);

    println!("out1: {:?}", out[0]);
    println!("out2: {:?}", out[1]);
}

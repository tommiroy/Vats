use curve25519_dalek::ristretto::RistrettoPoint;

use super::signOff;

// Aggregate signatures from multiple signers
pub fn sign_agg(outs: Vec<Vec<RistrettoPoint>>, v: u32) -> Vec<RistrettoPoint> {
    let mut out_temp = Vec::with_capacity(v as usize);
    for i in 0..v {
        let mut big_rs = Vec::<RistrettoPoint>::new();
        for j in 0..outs.len() {
            big_rs.push(outs[j][i as usize]);
        }
        out_temp.push(big_rs);
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

    let out = sign_agg(outs, 2);

    println!("out1: {:?}", out[0]);
    println!("out2: {:?}", out[1]);
}

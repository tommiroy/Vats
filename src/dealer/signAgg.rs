//  Imports 

use curve25519_dalek::ristretto::RistrettoPoint;


pub fn signAgg(Rs: Vec<Vec<RistrettoPoint>>) -> Vec<RistrettoPoint> {
    let rslen = Rs.len();
    let mut outs: Vec<Vec<RistrettoPoint>> = Vec::with_capacity(rslen); // Does this work????
    for i in 0..rslen {
        let mut out: Vec<RistrettoPoint>= Vec::with_capacity(rslen);
        for r in Rs.clone() {
            out.push(r[i]);
        }
        outs.push(out);
    }


    outs
}
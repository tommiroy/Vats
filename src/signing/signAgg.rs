use curve25519_dalek::ristretto::RistrettoPoint;

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



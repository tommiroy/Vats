use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use super::super::util::Committee;
use super::tilde_r::tilde_r;

pub fn signAgg2(
    out_prim: Vec<(RistrettoPoint, (Scalar, RistrettoPoint))>,
    out: Vec<RistrettoPoint>,
    com: Committee,
    m: String,
) -> Result<Scalar, Vec<u32>> {
    // let mut z = Scalar::zero();
    // for (i, _) in out_prim.iter().enumerate(){

    //     z += out_prim[i];
    // }
    let mut cheaters = Vec::<RistrettoPoint>::new();
    let tilde_R = tilde_r(com, out, m);
    for &out in out_prim.iter() {
        if out.0 != tilde_R {
            cheaters.push(out.1 .1);
        }
    }

    //let z = out_prim.iter().sum();
    // sum the Scalars in out_prim
    let mut z = Scalar::zero();
    for (i, _) in out_prim.iter().enumerate() {
        z += out_prim[i].1 .0;
    }

    if let Err(msg) = Ok(z) {
        return Err(msg);
    }
    // let rho = musig_coef(committee, big_ys[0]);
    return Ok(z);
}

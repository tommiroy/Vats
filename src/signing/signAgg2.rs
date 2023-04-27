use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use super::super::util::Committee;
use super::muSigCoef::musig_coef;

pub fn signAgg2(out_prim: Vec<Scalar>, committee: Committee) -> Scalar {
    // let mut z = Scalar::zero();
    // for (i, _) in out_prim.iter().enumerate(){

    //     z += out_prim[i];
    // }

    let z = out_prim.iter().sum();

    // let rho = musig_coef(committee, big_ys[0]);
    z
}

use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};

use super::header::Committee;
use super::muSigCoef::musig_coef;

pub fn signAgg2(out_prim: Vec<Scalar>, tilde_y: RistrettoPoint, big_ys: Vec<RistrettoPoint>, committee:Committee) -> Scalar {
    let mut z = Scalar::zero();
    for (i, _) in out_prim.iter().enumerate(){
        z += out_prim[i];
    }
    // let rho = musig_coef(committee, big_ys[0]);
    z
}

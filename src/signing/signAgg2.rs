use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};

use super::header::Committee;
use super::muSigCoef::musig_coef;

pub fn signAgg2(out_prim: Vec<Scalar>, tilde_y: RistrettoPoint, big_ys: Vec<RistrettoPoint>, committee:Committee) -> Scalar {
    let mut z = Scalar::zero();
    for (i, _) in out_prim.iter().enumerate(){
        let rho = musig_coef(committee.clone(), big_ys[i]);
        z += out_prim[i]*rho.invert();
        // Check if invert works correctly. Spoiler: It works!
        // println!("rho in signAgg2: {:?}", rho);
        // assert_eq!(rho*rho.invert(),Scalar::from(1_u32), "Invert in signAgg2 not working correctly");
    }
    // let rho = musig_coef(committee, big_ys[0]);
    z
}

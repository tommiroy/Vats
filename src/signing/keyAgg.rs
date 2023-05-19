use std::collections::HashMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use super::super::util::{compute_lagrange_coefficient, musig_coef, Committee};

// S is signing committee members public keys
pub fn key_agg(committee: Committee) -> Result<RistrettoPoint, &'static str> {
    if committee.signers.is_empty() {
        return Err(
            "Invalid input: L and participants must have non-zero length and the same length.",
        );
    }


    // println!("key_agg: {:?}", committee.signers.keys());

    let mut rho = HashMap::<u32, Scalar>::new();
    
    for (&id, &big_y) in committee.signers.iter() {
        rho.insert(id, musig_coef(committee.clone(), big_y));
    }
    let mut tilde_y = RistrettoPoint::identity();

    // $\widetilde{Y} : =  \prod^n_{i=1} \ Y_i^{\rho_{i} \lambda_i}$ where $\lambda_i$ is the Lagrange coefficient of $Y_i$
    // this enables us to verify that the share is part of the signing committee
    for (x, big_y) in committee.signers {
        tilde_y += big_y * rho.get(&x).unwrap();
    }
    Ok(tilde_y)
}

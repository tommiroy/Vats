use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use super::header::{compute_lagrange_coefficient, Committee};
use super::muSigCoef::musig_coef;

// S is signing committee members public keys
pub fn key_agg(committee: Committee) -> Result<RistrettoPoint, &'static str> {
    if committee.signers.is_empty() {
        return Err(
            "Invalid input: L and participants must have non-zero length and the same length.",
        );
    }

    let mut rho = Vec::<Scalar>::new();
    // for i in 0..L.len() { $\rho_i = MuSigCoef(L,Y_i)$ }S
    for y in committee.signers.iter() {
        rho.push(musig_coef(committee.clone(), y.public_key.key));
    }
    let mut tilde_y = RistrettoPoint::identity();

    // $\widetilde{Y} : =  \prod^n_{i=1} \ Y_i^{\rho_{i} \lambda_i}$ where $\lambda_i$ is the Lagrange coefficient of $Y_i$
    // this enables us to verify that the share is part of the signing committee
    for (i, x) in committee.signers.iter().enumerate() {
        let lagrange_coefficient = compute_lagrange_coefficient(committee.clone(), x.id);
        if lagrange_coefficient == Scalar::zero() {
            return Err("The Lagrange coefficient cannot be zero");
        }
        tilde_y += x.public_key.key * rho[i] * lagrange_coefficient;
    }
    Ok(tilde_y)
}

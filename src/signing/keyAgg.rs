use super::muSigCoef;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;

use super::header;

// S is signing committee members public keys
pub fn keyAgg(L: Vec<RistrettoPoint>, participants: Vec<u32>) -> RistrettoPoint {
    let mut rho = Vec::<Scalar>::new();
    // for i in 0..L.len() { $\rho_i = MuSigCoef(L,Y_i)$ }S
    for y in L.clone() {
        rho.push(muSigCoef::muSigCoef(L.clone(), y));
    }
    let mut tilde_y = RistrettoPoint::identity();

    // $\widetilde{Y} : =  \prod^n_{i=1} \ Y_i^{\rho_{i} \lambda_i}$ where $\lambda_i$ is the Lagrange coefficient of $Y_i$
    // this enables us to verify that the share is part of the signing committee
    for i in 0..L.len() {
        //prod of Each public key with rho as exponent
        tilde_y += L[i]
            * rho[i]
            * header::compute_lagrange_coefficient(participants.clone(), participants[i]);
    }
    tilde_y
}

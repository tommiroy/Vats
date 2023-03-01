use super::muSigCoef;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

// S is signing committee members public keys
pub fn keyAgg(S: Vec<RistrettoPoint>) -> RistrettoPoint {
    let mut rho = Vec::<Scalar>::new();
    for i in 0..S.len() {
        rho.push(muSigCoef::muSigCoef(S.clone(), S[i]));
    }
    let mut tilde_y = RistrettoPoint::identity();
    for i in 0..S.len() {
        //prod of Each public key with rho as exponent
        tilde_y += S[i] * rho[i];
    }
    tilde_y
}

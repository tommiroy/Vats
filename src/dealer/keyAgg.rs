use super::muSigCoef;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

// S is signing committee members public keys
pub fn keyAgg(S: Vec<RistrettoPoint>) -> Scalar {
    let mut rho = Vec::<Scalar>::new();
    for i in 0..S.len() {
        rho.push(muSigCoef::muSigCoef(S.clone(), S[i]));
    }
    let mut tilde_y = Scalar::one();
    for i in 0..S.len() {
        tilde_y *= Scalar::from_bytes_mod_order(*((S[i]) * (rho[i])).compress().as_bytes());
    }
    tilde_y
}

use super::muSigCoef;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;

// S is signing committee members public keys
pub fn keyAgg(L: Vec<RistrettoPoint>) -> RistrettoPoint {
    let mut rho = Vec::<Scalar>::new();

    for y in L.clone() {
        rho.push(muSigCoef::muSigCoef(L.clone(), y));

    }

    // for i in 0..L.len() {
    //     rho.push(muSigCoef::muSigCoef(L.clone(), S[i]));
    // }

    let mut tilde_y = RistrettoPoint::identity();

    for i in 0..L.len() {
        //prod of Each public key with rho as exponent
        tilde_y += L[i] * rho[i];
    }
    tilde_y
}

// Test for keyAgg
pub fn test_keyAgg() {
    // Honestly dont know how to test it...
    unimplemented!("Hello");
}
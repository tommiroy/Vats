use super::muSigCoef;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;

// S is signing committee members public keys
pub fn keyAgg(L: Vec<RistrettoPoint>, participants: Vec<u32>) -> RistrettoPoint {
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
        tilde_y +=
            L[i] * rho[i] * compute_lagrange_coefficient(participants.clone(), participants[i]);
    }
    tilde_y
}

pub fn compute_lagrange_coefficient(participants: Vec<u32>, x0: u32) -> Scalar {
    let mut li = Scalar::one();
    for x1 in participants.iter() {
        if *x1 != x0 {
            let lui = Scalar::from(*x1) * (Scalar::from(*x1) - Scalar::from(x0)).invert();
            li *= lui;
        }
    }

    li
}

// Test for keyAgg
pub fn test_keyAgg() {
    // Honestly dont know how to test it...
    unimplemented!("Hello");
}

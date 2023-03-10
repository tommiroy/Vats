use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;

pub fn test_ristretto() {

    let mut rng: OsRng = OsRng;
    let ris1 = RistrettoPoint::random(&mut rng);
    let ris2 = RistrettoPoint::random(&mut rng);

    let ris3 = ris1 + ris2;
}
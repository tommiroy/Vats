use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

mod key_dealer;

pub fn keygen(t: usize, n: usize) -> (Vec<(u32, Scalar)>, Vec<(u32, RistrettoPoint)>) {
    key_dealer::dealer(t, n)
}

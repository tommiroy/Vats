use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

pub fn muSigCoef(L: Vec<RistrettoPoint>, Y_i: RistrettoPoint) -> Scalar {
    let mut hasher = Sha512::new();
    for point in L.iter() {
        hasher.update(point.compress().as_bytes());
    }
    hasher.update(Y_i.compress().as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hash.as_slice());
    Scalar::from_bytes_mod_order_wide(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_mu_sig_coef() {
        // Generate some random inputs
        let mut rng = OsRng;
        let num_keys = 10;
        let L: Vec<RistrettoPoint> = (0..num_keys)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect();
        let Y_i = RistrettoPoint::random(&mut rng);

        // Compute the expected output
        let mut hasher = Sha512::new();
        for point in L.iter() {
            hasher.update(point.compress().as_bytes());
        }
        hasher.update(Y_i.compress().as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(hash.as_slice());
        let expected_output = Scalar::from_bytes_mod_order_wide(&bytes);

        // Test the function
        let output = muSigCoef(L, Y_i);
        assert_eq!(output, expected_output);
    }
}

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

// use rand::rngs::OsRng;

pub fn share_ver(
    big_b: Vec<(u32, RistrettoPoint)>,
    my_id: u32,
    share: Scalar,
    t: usize,
    n: usize,
) -> (Scalar, Vec<(u32, RistrettoPoint)>, RistrettoPoint) {
    // Verify the shares with Feldmans VSS
    let mut valid = true;
    let lhs = &RISTRETTO_BASEPOINT_TABLE * &share;
    let mut rhs = RistrettoPoint::identity();
    for j in 0..t {
        rhs += big_b[j].1 * scalar_pow(Scalar::from(my_id + 1), j as u32);
    }
    if lhs != rhs {
        valid = false;
    }
    assert!(valid, "Shares are not valid");

    let pk = big_b[0].1;
    (share, big_b, pk)
}

// #################### Helper functions ###########################
fn scalar_pow(base: Scalar, exp: u32) -> Scalar {
    let mut result = Scalar::one();
    for _ in 0..exp {
        result *= base;
    }
    result
}

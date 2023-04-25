use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use log::{debug, error, info, trace, warn};

// use rand::rngs::OsRng;

pub fn share_ver(
    big_bs: Vec<RistrettoPoint>,
    my_id: u32,
    share: Scalar,
    t: usize,
    n: usize,
) -> (Scalar, RistrettoPoint) {
    // Verify the shares with Feldmans VSS
    // let mut valid = true;
    let lhs = &RISTRETTO_BASEPOINT_TABLE * &share;
    let mut rhs = RistrettoPoint::identity();

    // for j in 0..t {
    //     rhs += big_b[j] * scalar_pow(Scalar::from(my_id), j as u32);
    // }
    // if lhs != rhs {
    //     valid = false;
    // }

    for (j, big_b) in big_bs.iter().enumerate() {
        rhs += big_b * scalar_pow(Scalar::from(my_id), j as u32);
    }
    // if lhs != rhs {
    //     valid = false;
    // }

    assert_eq!(lhs, rhs, "My share is not valid");

    let pk = big_bs[0];

    info!("Successfully verified share and pk from dealer");
    (share, pk)
}

// #################### Helper functions ###########################
fn scalar_pow(base: Scalar, exp: u32) -> Scalar {
    let mut result = Scalar::one();
    for _ in 0..exp {
        result *= base;
    }
    result
}

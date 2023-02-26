use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;



// Generate a threshold Shamir secret sharing with Feldman VSS
pub fn keygen(t: usize, n: usize) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
    let mut rng: OsRng = OsRng;

    // Dealer samples t random values
    let mut a: Vec<Scalar> = Vec::with_capacity(t);
    for _ in 0..t {
        a.push(Scalar::random(&mut rng));
    }

    println!("a: {:?}", a);

    // Calculate the shares
    let mut shares = Vec::with_capacity(t);
    for i in 0..n {
        let mut coeff = Scalar::zero();
        for j in 0..t {
            coeff += a[j] * Scalar::from((i+1).pow(j as u32) as u32);
        }
        shares.push(coeff);
    }

    // Generate the commitments which will be broadcasted
    let mut B = Vec::with_capacity(t);
    for j in 0..t {
        B.push(&RISTRETTO_BASEPOINT_TABLE * &a[j]);
    }

    // Generate the public keys
    let mut pks = Vec::with_capacity(n);
    for i in 0..n {
        pks.push(&RISTRETTO_BASEPOINT_TABLE * &shares[i]);
    }


    // Verify the shares
    let mut valid = true;
    for i in 0..n {
        let lhs = &RISTRETTO_BASEPOINT_TABLE * &shares[i];
        let mut rhs = RistrettoPoint::identity();
        for j in 0..t {
            rhs += B[j] * (Scalar::from((i+1).pow(j as u32)as u32));
        }
        if lhs != rhs {
            valid = false;
            break;
        }
    }
    assert!(valid, "Shares are not valid");
    
    
    (shares, pks)
}

pub fn reconstruct_secret_key(shares: &[Scalar]) -> Scalar {
    let n = shares.len();
    let mut secret = Scalar::zero();

    for i in 0..n {
        let mut numerator = Scalar::one();
        let mut denominator = Scalar::one();

        for j in 0..n {
            if i != j {
                numerator *= Scalar::from((j+1) as u64);
                denominator *= Scalar::from((j+1-i) as u64);
            }
        }

        secret += shares[i] * numerator * denominator.invert();
    }

    secret
}
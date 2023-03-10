use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;

// Generate a threshold Shamir secret sharing with Feldman VSS
pub fn dealer(t: usize, n: usize) -> (Vec<(u32, Scalar)>, Vec<(u32, RistrettoPoint)>, RistrettoPoint, Scalar) {
    let mut rng: OsRng = OsRng;

    // Dealer samples t random values t-1 a   ----> t = 3
    let mut a: Vec<Scalar> = Vec::with_capacity(t);
    for _ in 0..t {
        a.push(Scalar::random(&mut rng));
    }

    // println!("Secret in keygen: {:?}", a[0]);

    // Calculate the shares    // Dealer samples t random values t-1 a   ----> t = 3
    // Dealer samples t random values t-1 a   ----> t = 3

    let mut shares = Vec::with_capacity(t);
    for i in 0..n {
        let mut share = Scalar::zero();
        for j in 0..t {
            share += a[j] * Scalar::from((i + 1).pow(j as u32) as u32);
        }
        shares.push(((i + 1) as u32, share));
    }

    // Generate the commitments which will be broadcasted 0<=j<=t
    let mut B = Vec::with_capacity(n);
    for j in 0..t {
        B.push(&RISTRETTO_BASEPOINT_TABLE * &a[j]);
    }

    // Generate the public keys G^si
    let mut pks = Vec::with_capacity(n);
    for i in 0..n {
        pks.push((
            (i + 1) as u32,
            &RISTRETTO_BASEPOINT_TABLE * &shares.clone()[i].1,
        ));
    }

    //Calculate the public key G^s
    //let mut sk = Scalar::zero();
    //for i in 0..t {
    //    sk += &shares[i].1;
    //}
    //let pk = &RISTRETTO_BASEPOINT_TABLE * &sk;

    // Verify the shares with Feldmans VSS
    let mut valid = true;
    for i in 0..n {
        let lhs = &RISTRETTO_BASEPOINT_TABLE * &shares[i].1;
        let mut rhs = RistrettoPoint::identity();
        for j in 0..t {
            rhs += B[j] * (Scalar::from((i + 1).pow(j as u32) as u32));
        }
        if lhs != rhs {
            valid = false;
            break;
        }
    }
    assert!(valid, "Shares are not valid");

    let pk = &RISTRETTO_BASEPOINT_TABLE * &a[0];
    (shares, pks, pk, a[0])
}

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;

// Generate a threshold Shamir secret sharing with Feldman VSS
pub fn dealer(
    t: usize,
    n: usize,
) -> (
    Vec<(u32, Scalar)>,
    Vec<(u32, RistrettoPoint)>,
    RistrettoPoint,
    Scalar,
    Vec<RistrettoPoint>,
) {
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
    for i in 1..n + 1 {
        let mut share = Scalar::zero();
        for j in 0..a.len() {
            share += a[j] * scalar_pow(Scalar::from(i as u32), j as u32);
        }
        shares.push((i as u32, share));
    }

    // Generate the commitments which will be broadcasted 0<=j<=t
    let mut big_b = Vec::with_capacity(n);
    for ai in a.clone() {
        big_b.push(&RISTRETTO_BASEPOINT_TABLE * &ai);
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
            // rhs += B[j] * scalar_pow(Scalar::from(i as u8), j as u32);
            // rhs += B[j] * Scalar::from(i as u32 +1) * Scalar::from(j as u128);
            rhs += big_b[j] * scalar_pow(Scalar::from(i as u32 + 1), j as u32);
        }
        if lhs != rhs {
            valid = false;
            break;
        }
    }
    assert!(valid, "Shares are not valid");

    // let mut sk_prim = Scalar::zero();
    // for (i, x) in &shares.clone() {
    //     sk_prim += x * compute_lagrange_coefficient(shares.clone(), *i);
    //     if sk_prim == a[0] {
    //         println!("################### Secret keys: EQUAL! ###################");
    //     }
    // }

    // assert_eq!(sk_prim, a[0], "key reconstruction is wrong in key_dealer");

    let pk = &RISTRETTO_BASEPOINT_TABLE * &a[0];
    (shares, pks, pk, a[0], big_b)
}

// #################### Helper functions ###########################

fn scalar_pow(base: Scalar, exp: u32) -> Scalar {
    let mut result = Scalar::one();
    for _ in 0..exp {
        result *= base;
    }
    result
}

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
    for i in 1..n+1 {
        let mut share = Scalar::zero();
        for j in 0..a.len() {
            share += a[j] * scalar_pow(Scalar::from(i as u8), j as u32);
        }
        shares.push((i as u32, share));
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
    for i in 1..n+1 {
        let lhs = &RISTRETTO_BASEPOINT_TABLE * &shares[i].1;
        let mut rhs = RistrettoPoint::identity();
        for j in 0..t {
            // rhs += B[j] * scalar_pow(Scalar::from(i as u8), j as u32);
            rhs += B[j] * Scalar::from(i as u8) * Scalar::from(j as u128);

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
    (shares, pks, pk, a[0])
}


// #################### Helper functions ###########################

// Compute larange coefficient
// Used in key aggregation and signing
pub fn compute_lagrange_coefficient(shares: Vec<(u32, Scalar)>, x0: u32) -> Scalar {
    let mut lagrange_coefficient = Scalar::one();

    // Standard lagrange coefficient calculation
    // https://en.wikipedia.org/wiki/Lagrange_polynomial
    for (x1,_) in shares {
        if x1 != x0 {
            println!("x1={}   x0={}", x1, x0);
            let calc = Scalar::from(x1) * (Scalar::from(x1) - Scalar::from(x0)).invert();
            lagrange_coefficient *= calc;
        }
    }
    lagrange_coefficient
}



fn scalar_pow(base: Scalar, exp: u32) -> Scalar {   
    let mut result = Scalar::one();
    for _ in 0..exp {
        result *= base;
    }
    result
}

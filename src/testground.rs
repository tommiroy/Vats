use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;

pub fn test_ristretto() {

    let mut rng: OsRng = OsRng;
    let ris = RistrettoPoint::random(&mut rng);

    // assert_eq!(ris*Scalar::from(4 as u32), ris*Scalar::from(1 as u32)+ris*Scalar::from(3 as u32));

    let a = Scalar::from_bytes_mod_order(*ris.compress().as_bytes());


    if let Some(b) = CompressedRistretto::decompress(&CompressedRistretto::from_slice(a.as_bytes())) {
        // println!("Success!");
        // assert_eq!(b*Scalar::from(3 as u32), ris);
        let b_scalar = Scalar::from_bytes_mod_order(*b.compress().as_bytes());
        // assert_eq!(b_scalar, a);
        
        let risoo = &RISTRETTO_BASEPOINT_TABLE * &a;
        let risooo = &RISTRETTO_BASEPOINT_POINT * &b_scalar;

        if (risoo == risooo) {
            println!("Equal!!!!!");
        } else {
            print!("Not Equal!!!");
        }
        // assert_eq!(risoo, risooo);

    }  

}
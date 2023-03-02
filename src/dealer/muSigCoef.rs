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


// Test for muSigCoef
use rand::rngs::OsRng;

pub fn test_muSigCoef () {
    let mut rng: OsRng = OsRng;
    let yi = RistrettoPoint::random(&mut rng);
    let yother = RistrettoPoint::random(&mut rng);
    let bigL = vec![RistrettoPoint::random(&mut rng), 
                                        RistrettoPoint::random(&mut rng),
                                        RistrettoPoint::random(&mut rng),
                                        RistrettoPoint::random(&mut rng),
                                        yi.clone()];

    assert_eq!(muSigCoef(bigL.clone(), yi.clone()), muSigCoef(bigL.clone(), yi.clone()),
                "muSigCoef generates different output from same inputs!");
    
    assert_ne!(muSigCoef(bigL.clone(), yother), muSigCoef(bigL.clone(), yi.clone()),
            "muSigCoef generates same output from different inputs!");

    println!("Finished testing MuSigCoef. All tests passed!");
}
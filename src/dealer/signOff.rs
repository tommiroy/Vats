use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;

pub fn signOff(v: u32) -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut state1 = Vec::<Scalar>::new();
    let mut out1 = Vec::<RistrettoPoint>::new();
    for j in 0..v {
        let mut rand = OsRng;
        let r = Scalar::random(&mut rand);
        state1.push(r);
        out1.push(&RISTRETTO_BASEPOINT_TABLE * &r);
    }
    return (out1, state1);
}

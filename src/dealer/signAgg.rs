
use curve25519_dalek::scalar::Scalar;

pub fn signAgg(out: Vec<Scalar>, v: u32) -> Scalar {
    let mut outi = Vec::<Scalar>::new();
    for i in 0..v {
        outi.push(out[i as usize]);
    }
    let mut rj = Scalar::one();
    for i in 0..v {
        rj *= outi[i as usize];
    }
    rj
}

use curve25519_dalek::scalar::Scalar;

pub fn SignAgg2(out_prim: Vec<Scalar>) -> Scalar {
    let mut z = Scalar::zero();
    for i in 0..out_prim.len() {
        z += out_prim[i];
    }
    z
}

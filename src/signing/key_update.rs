use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use super::header::Committee;

pub fn key_update(si: Scalar, t: u32 , nonce: Scalar, committee: Committee) {
    let mut rng: OsRng = OsRng;
    // Create t-1 random values as coefficients in f(x)
    // f(0) = s_i
    let n = committee.signers.len();
    let mut coefs: Vec<Scalar> = Vec::with_capacity(t as usize);
    coefs.push(si);
    for _ in 0..t-1 {
        coefs.push(Scalar::random(&mut rng));
    }
    // Create new share parts
    let mut new_shares = Vec::<(u32, Scalar)>::new();
    for signer in committee.signers {
        let mut new_share = Scalar::zero();
        for (i,a) in coefs.iter().enumerate() {
            new_share += a * Scalar::from(signer.id.pow(i as u32));
        }
        new_shares.push((signer.id, new_share));
    }

    // Create whatever. Committment?
    let k = Scalar::random(&mut rng);
    let big_r = &RISTRETTO_BASEPOINT_TABLE * &k;

}
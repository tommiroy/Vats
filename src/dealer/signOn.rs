use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use flume::Receiver;
use rand::rngs::OsRng;
use sha2::digest::typenum::private::PrivateIntegerAdd;

use crate::dealer::keyAgg::keyAgg;
use crate::dealer::keygen::keygen;
use crate::dealer::muSigCoef::muSigCoef;
use crate::dealer::signAgg::signAgg;
use crate::dealer::signOff::signOff;

use sha2::{Digest, Sha512};

pub fn SignOn(
    state1: Vec<Scalar>,
    out: Vec<RistrettoPoint>,
    m: String,
    sk: (u32, Scalar),
    pk: RistrettoPoint,
    L: Vec<RistrettoPoint>,
    t: u32,
    n: u32,
    v: u32,
) -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut r_list = Vec::<Scalar>::new();
    let rho_i = muSigCoef(L, pk);
    let tilde_y = keyAgg(L);
    // hash b_pre with sha512
    let b = hash_non(tilde_y, out, m);

    // prod = out[i].pow(b.pow(j-1))
    for i in 0..v {
        let mut prod = RistrettoPoint::identity();
        for j in 0..n {
            prod = prod + out[i as usize].pow(b.pow(j as u32));
        }
        r_list.push(prod.compress().decompress().unwrap().x);
    }

    // For hashing the message with sha512 and returning a Scalar hashing PK, (R,..R), m
    fn hash_non(tilde_y: Scalar, out: Vec<RistrettoPoint>, m: String) -> Scalar {
        let b_pre = (tilde_y, out, m);
        let mut hasher = Sha512::new();
        // hash b_pre
        hasher.update(b_pre.0.as_bytes());
        for i in 0..b_pre.1.len() {
            hasher.update(b_pre.1[i].compress().as_bytes());
        }
        hasher.update(b_pre.2.as_bytes());
        let b = hasher.finalize();

        let result = hasher.finalize();
        let mut result_bytes = [0u8; 64];
        result_bytes.copy_from_slice(&result);
        Scalar::from_bytes_mod_order_wide(&result_bytes)
    }
}

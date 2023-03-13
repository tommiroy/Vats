use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
// use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

use rand::rngs::OsRng;

use super::header::*;

use vats::networkinterface;

pub async fn key_upd(
    t: usize,
    n: usize,
    Signer: &mut Signer,
    Context: &str,
) -> (
    Vec<(u32, Scalar)>,
    Vec<(u32, RistrettoPoint)>,
    RistrettoPoint,
    Scalar,
) {
    {
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
                share += Signer.private_key.get_key()
                    + a[j] * Scalar::from((i + 1).pow(j as u32) as u32);
            }
            shares.push(((i + 1) as u32, share));
        }

        // Generate the commitments which will be broadcasted 0<=j<=t
        let mut mini_sigma = Vec::with_capacity(n);
        for j in 0..t {
            mini_sigma.push(&RISTRETTO_BASEPOINT_TABLE * &a[j]);
        }

        // Generate Nonce k
        let mut rand = OsRng;
        let k = Scalar::random(&mut rand);

        // Compute Response R = G^k
        let big_r_i = &RISTRETTO_BASEPOINT_TABLE * &k;

        // Compute Challange c = H(i,Context,g^a_{i0}, Ri)
        let c_i = hash_key(Signer.id, Context.to_string(), mini_sigma[0], big_r_i);

        // Compute mu = k + a_{i0} * ci
        let mu_i = k + a[0] * c_i;

        // Compute the public commitment
        let commitments = Vec::with_capacity(t);

        for i in 1..t {
            commitments.push(mini_sigma[i]);
        }
        let rx = networkinterface::get_receive_channel("key_upd".to_string()).await;

        let sigma_i = (big_r_i, mu_i);

        //------------------------------------Broadcast --------------------------------------

        let sigma_i_string = (point_to_string(sigma_i.0), scalar_to_string(&sigma_i.1));
        let mut commitments_string = Vec::with_capacity(t);
        for i in commitments {
            commitments_string.push(point_to_string(i));
        }

        // make sigma_i_string and commitments_string a string
        let sigma_i_string = serde_json::to_string(&sigma_i_string).unwrap();
        // make commitments_string a string
        let commitments_string = serde_json::to_string(&commitments_string).unwrap();

        //BROADCAST commitments, sigma = (big_r_i, mu_i);

        networkinterface::cast(("key_upd").to_string(), sigma_i_string).await;
        networkinterface::cast(("key_upd").to_string(), commitments_string).await;

        //Upon receiving all commitments, verify sigma_l = (big_r_l, mu_l). 1<=l<=n l/=i
        //Verify that c_l = H(l,Context,g^a_{l0}, R_l)
        //Verify that R_l = G^mu_l * mini_sigma^-c_l
        //upon verification, Delete {minisigma_l, 1<=l<=n}

        // Round Two

        (shares, pks, pk, a[0])
    }
}

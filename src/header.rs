use std::collections::HashMap;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

pub struct Signer {
    // Participant's index
    pub id: u32,
    // Participant's group public key
    pub group_pubkey: PublicKey,
    // Participant's public key
    pub pubkeys: HashMap<u32, PublicKey>,
    // Participant's private key
    share: Scalar,
}

impl Signer {
    pub fn new(id:u32) -> Signer{
        Signer { id: id, group_pubkey: PublicKey::new(id), pubkeys: HashMap::new(), share: Scalar::zero()}
    }

}

pub struct PublicKey {
    pub id: u32,
    pub pubkey: RistrettoPoint,
}
// 
impl PublicKey {

    pub fn new(id:u32) -> PublicKey{
        PublicKey {id:id, pubkey: RISTRETTO_BASEPOINT_POINT}
    }

    pub fn to_scalar (&self) -> Scalar {
        Scalar::from_bytes_mod_order(*self.pubkey.compress().as_bytes())
    }
}


// --------------- TEST -----------------------------

// pub fn test_to_scalar() {
//     let var1 = Scalar::from(8 as u32);
//     let mut key = PublicKey::new(3);
//     if let Ok(a) =CompressedRistretto::from_slice(var1.as_bytes()).decompress() {

//     }
//     let var1converted = key.to_scalar();

//     assert_eq!(var1,var1converted);
// }


// pub fn compute_lagrange_coeff(is: Vec<f32>, i:f32) -> f32 {
//     let mut li = 1.0;
//     for j in is {
//         if i==j {
//             continue;
//         }
//         println!("{}/({}-{}) = {}", j,j,i,li);

//         li *= j/(j-i);
//         println!("{}/({}-{}) = {}", j,j,i,li);
//     }
//     li
// }


pub(crate) fn compute_lagrange_coeff( participant_index: &u32, all_participant_indices: &[u32]) -> Scalar {
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    let mine = Scalar::from(*participant_index);

    for j in all_participant_indices.iter() {
        if j == participant_index {
            continue;
        }
        let s = Scalar::from(*j);

        num *= s;
        den *= s - mine; // Check to ensure that one person isn't trying to sign twice.
    }
    num * den.invert()
}

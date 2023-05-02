use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use super::tilde_r::calculate_tilde_r;
use ::log::*;
use super::super::util::*;
use super::super::server::Server;
use super::signAgg::sign_agg;

pub fn signAgg2(
    server: &Server,
    // out_prim: Vec<(RistrettoPoint, (Scalar, RistrettoPoint))>,
    // out: Vec<RistrettoPoint>,
    // com: Committee,
    // m: String,
) -> Result<Scalar, Vec<u32>> {
    // let mut z = Scalar::zero();
    // for (i, _) in out_prim.iter().enumerate(){

    //     z += out_prim[i];
    // }
    

    let mut cheaters = Vec::<RistrettoPoint>::new();
    let committee = Committee::new(server.committee.clone());
    let out = Vec::<Vec<RistrettoPoint>>::new();
    for signer in committee.signers {
        out.push(server.nonces.get(signer.id))
    }
    // let out = sign_agg(server.nonces.values().collect(), 2);

    let tilde_r = calculate_tilde_r(committee, out, m);
    for &out in out_prim.iter() {
        if out.0 != tilde_r {
            cheaters.push(out.1 .1);
        }
    }




        warn!("Recieved signature from: {:?}", id);
        // "recreating client varibles" rhs
        let &bigy_x = server.pubkeys.get(&id).unwrap();
        warn!("big_yx: {:?}", point_to_string(bigy_x));
        let rho_x = musig_coef(committee.clone(), bigy_x);
        warn!("rho_x: {:?}", scalar_to_string(&rho_x));

        let lambda_x = compute_lagrange_coefficient(committee.clone(), id);
        warn!("lambda_x: {:?}", scalar_to_string(&lambda_x));

        // let tilde_r = tilde_r(committee, self.agg1.clone(), self.m.clone());
        // warn!("tilde_r: {:?}", point_to_string(tilde_r));

        let c_x = hash_sig(server.vehkey, tilde_rx, self.m.clone());

        warn!("c_x: {:?}", scalar_to_string(&c_x));

        // Verification of Partial signatures lhs
        let ver = &RISTRETTO_BASEPOINT_TABLE * &zx;

        ///
        if ver == bigR_x + bigy_x * (c_x * (rho_x + lambda_x)) {

    //let z = out_prim.iter().sum();
    // sum the Scalars in out_prim
    let mut z = Scalar::zero();
    for (i, _) in out_prim.iter().enumerate() {
        z += out_prim[i].1 .0;
    }

    if let Err(msg) = Ok(z) {
        return Err(msg);
    }
    // let rho = musig_coef(committee, big_ys[0]);
    Ok(z)
}

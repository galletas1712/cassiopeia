use std::iter;

use crate::{errors::*, structs::*};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use rand::thread_rng;

use ark_bn254::{Fr, G2Affine};
use num_bigint::RandBigInt;

pub fn distribute_secret(
    pvss_config: &PVSSConfig,
) -> Result<(PVSSCiphertext, PVSSSecrets), PVSSError> {
    let mut rng = thread_rng();

    // Secret needs to be <= 250 bits for circom compatibility
    let f_0 = Fr::from(rng.gen_biguint(250));
    let f = iter::once(f_0).chain((1..pvss_config.t)
        .map(|_| Fr::rand(&mut rng)))
        .collect::<Vec<_>>();

    let y_eval_i = (1..=pvss_config.committee_pks.len())
        .map(|i| {
            let x = Fr::from(i as i64);
            f.iter()
                .scan(Fr::one(), |x_pow, &c| {
                    let prev_x_pow = *x_pow;
                    *x_pow *= x;
                    Some(c * prev_x_pow)
                })
                .fold(Fr::zero(), |acc, x| acc + x)
        })
        .collect::<Vec<_>>();

    // NOTE: includes secret f[0] itself
    let f_i = f
        .iter()
        .map(|a| {
            pvss_config
                .pairing_config
                .g
                .mul(a.into_repr())
                .into_affine()
        })
        .collect::<Vec<_>>();

    let a_i = y_eval_i
        .iter()
        .map(|a| {
            pvss_config
                .pairing_config
                .g
                .mul(a.into_repr())
                .into_affine()
        })
        .collect::<Vec<_>>();

    let y_i = y_eval_i
        .iter()
        .enumerate()
        .map::<Result<G2Affine, PVSSError>, _>(|(i, a)| {
            Ok(pvss_config
                .committee_pks
                .get(i)
                .ok_or(PVSSError::InvalidParticipantId(i))?
                .mul(a.into_repr())
                .into_affine())
        })
        .collect::<Result<_, _>>()?;

    let pvss_ciphertext = PVSSCiphertext { f_i, a_i, y_i };

    let h_f_0 = pvss_config.pairing_config.h.mul(f[0]).into_affine();

    let pvss_secrets = PVSSSecrets { f_0: f[0], h_f_0 };

    Ok((pvss_ciphertext, pvss_secrets))
}

use crate::{errors::*, structs::*};
use ark_bn254::{Bn254, Fr, G1Projective, G2Affine};
use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use rand::Rng;
use std::ops::Neg;

fn gen_lagrange_coefficients(x: Vec<Fr>, alpha: Fr) -> Vec<Fr> {
    x.iter()
        .map(|x_i| {
            let mut coeff = Fr::one();
            for x_j in x.iter() {
                if x_i == x_j {
                    continue;
                }
                coeff *= (alpha - x_j) * (*x_i - *x_j).inverse().unwrap();
            }
            coeff
        })
        .collect::<Vec<_>>()
}

pub fn verify<R: Rng>(
    pvss_config: &PVSSConfig,
    ciphertext: &PVSSCiphertext,
    rng: &mut R,
) -> Result<(), PVSSError> {
    // Verify evaluations are correct probabilistically.
    let alpha = Fr::rand(rng);
    let lagrange_coefficients = gen_lagrange_coefficients(
        (1..=pvss_config.committee_pks.len())
            .map(|i| Fr::from(i as i64))
            .collect::<Vec<_>>(),
        alpha,
    );

    {
        let mut bases = vec![];
        bases.extend_from_slice(&ciphertext.a_i);
        let mut scalars = lagrange_coefficients
            .iter()
            .map(|l| l.into_repr())
            .collect::<Vec<_>>();
        let powers_of_alpha = {
            let mut current_alpha = Fr::one().neg();
            let mut powers = vec![];
            for _ in 0..=pvss_config.t {
                powers.push(current_alpha.into_repr());
                current_alpha *= &alpha;
            }
            powers
        };
        bases.extend_from_slice(&ciphertext.f_i);
        scalars.extend_from_slice(&powers_of_alpha.as_slice());
        let product = VariableBaseMSM::multi_scalar_mul(&bases, &scalars);
        if !product.is_zero() {
            return Err(PVSSError::EvaluationsCheckError(product.into()));
        }
    }

    // Verify same ratio. Need this for security proof.
    // let pairs = [
    //     (ciphertext.f_i[0].into(), self.pairing_config.u_1.into()),
    //     (self.pairing_config.g.neg().into(), ciphertext.u_2.into()),
    // ];
    // if !E::product_of_pairings(pairs.iter()).is_one() {
    //     return Err(PVSSError::RatioIncorrect);
    // }

    let powers_of_alpha = {
        let mut current_alpha = Fr::one();
        let mut powers = vec![];
        for _ in 0..pvss_config.committee_pks.len() {
            powers.push(current_alpha.into_repr());
            current_alpha *= &alpha;
        }
        powers
    };

    // NOTE: need -g because we check e(g, ...) = e(..., ...) -> e(..., ...) / e(-g, ...) = 1
    let (batched_a_i, batched_g_neg) = {
        let g_neg = pvss_config.pairing_config.g.neg();
        let batched_a_i = ciphertext
            .a_i
            .iter()
            .zip(powers_of_alpha.iter())
            .map(|(a, power)| a.mul(*power))
            .collect::<Vec<_>>();
        let batched_g_neg = powers_of_alpha
            .iter()
            .map(|power| g_neg.mul(*power))
            .collect::<Vec<_>>();
        let mut batched_all = vec![];
        batched_all.extend_from_slice(&batched_a_i);
        batched_all.extend_from_slice(&batched_g_neg);
        let batched_all = G1Projective::batch_normalization_into_affine(&batched_all);
        let batched_a_i = batched_all[..batched_a_i.len()]
            .into_iter()
            .map(|x| x.clone())
            .collect::<Vec<_>>();
        let batched_g_neg = batched_all[batched_a_i.len()..]
            .into_iter()
            .map(|x| x.clone())
            .collect::<Vec<_>>();
        (batched_a_i, batched_g_neg)
    };

    // Verify evaluations are encrypted correctly.
    let pairs = batched_a_i
        .into_iter()
        .zip(ciphertext.y_i.iter())
        .zip(batched_g_neg.into_iter())
        .enumerate()
        .map(|(i, ((a, y), g_neg))| {
            let pk = pvss_config
                .committee_pks
                .get(i)
                .ok_or(PVSSError::InvalidParticipantId(i))?;
            let pairs = vec![(g_neg.into(), (*y).into()), (a.into(), (*pk).into())];

            Ok(pairs)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if !Bn254::product_of_pairings(pairs.iter()).is_one() {
        return Err(PVSSError::RatioIncorrect);
    }
    Ok(())
}

pub fn verify_share(
    pvss_config: &PVSSConfig,
    pvss_ciphertext: &PVSSCiphertext,
    decrypted_share: G2Affine,
    i: usize,
) -> Result<(), PVSSError> {
    let g_neg = pvss_config.pairing_config.g.neg();
    let pairs = vec![
        (g_neg.into(), decrypted_share.into()),
        (
            pvss_ciphertext.a_i[i].into(),
            pvss_config.pairing_config.h.into(),
        ),
    ];
    if !Bn254::product_of_pairings(pairs.iter()).is_one() {
        return Err(PVSSError::RatioIncorrect);
    }
    Ok(())
}

// Assumes everything has already been verified
pub fn combine_shares(
    decrypted_shares: &Vec<G2Affine>,
    indices: &Vec<usize>,
) -> Result<G2Affine, PVSSError> {
    // Recombine secrets
    let x = indices
        .iter()
        .map(|i| Fr::from((*i + 1) as i64))
        .collect::<Vec<_>>();
    let lagrange_coefficients = gen_lagrange_coefficients(x, Fr::zero())
        .iter()
        .map(|l| l.into_repr())
        .collect::<Vec<_>>();

    let product =
        VariableBaseMSM::multi_scalar_mul(&decrypted_shares, &lagrange_coefficients).into_affine();
    Ok(product)
}

use crate::{errors::*, structs::*};

use ark_bn254::{Fr, G2Affine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};

// Verify share in here as well
pub fn decrypt_share(
    pvss_ciphertext: &PVSSCiphertext,
    sk: &Fr,
    i: usize,
) -> Result<G2Affine, PVSSError> {
    let sk_inverse = sk.inverse().ok_or(PVSSError::InvalidSecretKeyError)?;
    let decrypted_share = pvss_ciphertext.y_i[i]
        .mul(sk_inverse.into_repr())
        .into_affine();
    Ok(decrypted_share)
}

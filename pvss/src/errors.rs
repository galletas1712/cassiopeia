use ark_bn254::G1Affine;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PVSSError {
    #[error("Ratio incorrect")]
    RatioIncorrect,
    #[error("Evaluations are wrong: product = {0}")]
    EvaluationsCheckError(G1Affine),
    #[error("Could not generate evaluation domain")]
    InvalidParticipantId(usize),
    #[error("Invalid secret key error")]
    InvalidSecretKeyError,
}

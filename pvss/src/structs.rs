use ark_bn254::{g1, g2, Fr, G1Affine, G2Affine};

pub struct PairingConfig {
    pub g: G1Affine,
    pub h: G2Affine,
}

pub struct PVSSConfig {
    pub pairing_config: PairingConfig,
    pub committee_pks: Vec<G2Affine>,
    pub t: usize,
}

pub struct PVSSCiphertext {
    pub f_i: Vec<G1Affine>,
    pub a_i: Vec<G1Affine>,
    pub y_i: Vec<G2Affine>,
}

pub struct PVSSSecrets {
    pub f_0: Fr,
    pub h_f_0: G2Affine,
}

impl PairingConfig {
    pub fn new() -> Self {
        PairingConfig {
            g: G1Affine::new(g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y, false),
            h: G2Affine::new(g2::G2_GENERATOR_X, g2::G2_GENERATOR_Y, false),
        }
    }
}

impl PVSSConfig {
    pub fn new(pairing_config: PairingConfig, committee_pks: Vec<G2Affine>, t: usize) -> Self {
        assert!(t < committee_pks.len());
        PVSSConfig {
            pairing_config,
            committee_pks,
            t,
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::{committee::*, dealer::*, public::*, structs::*};
    use ark_bn254::Fr;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{PrimeField, UniformRand};
    use rand::seq::IteratorRandom;
    use rand::thread_rng;

    #[test]
    fn share_secret() {
        let mut rng = thread_rng();
        let n: usize = 10; // TODO: test with non-powers of 2 (might not be able to use
                           // Radix2EvaluationDomain)
        let t: usize = 5;
        let pairing_config = PairingConfig::new();
        let committee_sks = (1..=n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let committee_pks = committee_sks
            .iter()
            .map(|sk| pairing_config.h.mul(sk.into_repr()).into_affine())
            .collect::<Vec<_>>();
        let pvss_config = PVSSConfig::new(pairing_config, committee_pks, t);
        let (pvss_ciphertext, pvss_secrets) = distribute_secret(&pvss_config).unwrap();

        verify(&pvss_config, &pvss_ciphertext, &mut rng).unwrap();

        // Number of shares actually decrypted > t
        let k = 6;
        let indices_sample = (0..n).choose_multiple(&mut rng, k);
        let decrypted_shares = indices_sample
            .iter()
            .map(|i| {
                let share = decrypt_share(&pvss_ciphertext, &committee_sks[*i], *i).unwrap();
                let share2 = share.clone();
                verify_share(&pvss_config, &pvss_ciphertext, share2, *i).unwrap();
                share
            })
            .collect::<Vec<_>>();

        let decrypted_secret =
            combine_shares(&decrypted_shares, &indices_sample).unwrap();
        assert_eq!(decrypted_secret, pvss_secrets.h_f_0);

        // Number of shares actually decrypted <= t
        let k = 4;
        let indices_sample = (0..n).choose_multiple(&mut rng, k);
        let decrypted_shares = indices_sample
            .iter()
            .map(|i| {
                let share = decrypt_share(&pvss_ciphertext, &committee_sks[*i], *i).unwrap();
                let share2 = share.clone();
                verify_share(&pvss_config, &pvss_ciphertext, share2, *i).unwrap();
                share
            })
            .collect::<Vec<_>>();

        let decrypted_secret =
            combine_shares(&decrypted_shares, &indices_sample).unwrap();
        assert_ne!(decrypted_secret, pvss_secrets.h_f_0);
    }
}

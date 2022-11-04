use ark_bn254::{Fr, G2Affine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand};
use clap::{Parser, Subcommand};
use rand::thread_rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{error::Error, io};

use cassiopeia::{
    committee::decrypt_share,
    dealer::distribute_secret,
    public::{combine_shares, verify_ciphertext},
    serialize::*,
    structs::{PVSSCiphertext, PVSSConfig, PVSSSecrets, PairingConfig},
};

#[derive(Parser, Debug)]
#[command(author, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates n secret key and public key pairs
    #[command(arg_required_else_help = true)]
    GenKeys { n: usize },
    /// Generates PVSS ciphertext and secrets for threshold t
    #[command(arg_required_else_help = true)]
    DealSecret { t: usize },
    /// Decrypts a share at a specified index in the ciphertext with a secret key
    #[command()]
    DecryptShare,
    /// Combines decrypted shares to produce a secret
    #[command()]
    CombineShares,
    /// Verifies PVSS ciphertext
    #[command()]
    VerifyCiphertext,
}

#[derive(Serialize)]
struct GenKeysOutput {
    sks: Vec<FrSerializable>,
    pks: Vec<G2AffineSerializable>,
}

#[derive(Serialize)]
struct DealSecretOutput {
    ciphertext: PVSSCiphertext,
    secrets: PVSSSecrets,
}

#[derive(Deserialize)]
struct DecryptShareInput {
    i: usize,
    ciphertext: PVSSCiphertext,
    sk: FrSerializable,
}

#[derive(Deserialize)]
struct CombineSharesInputElem {
    i: usize,
    share: G2AffineSerializable,
}

#[derive(Deserialize)]
struct VerifyCiphertextInput {
    t: usize,
    pks: Vec<G2AffineSerializable>,
    ciphertext: PVSSCiphertext,
}

fn gen_keys(pairing_config: &PairingConfig, n: usize) -> GenKeysOutput {
    let mut rng = thread_rng();
    let sks = (0..n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let pks = sks
        .iter()
        .map(|sk| pairing_config.h.mul(sk.into_repr()).into_affine())
        .collect::<Vec<_>>();
    let sks_serializable = sks
        .iter()
        .map(|sk: &Fr| (*sk).into())
        .collect::<Vec<FrSerializable>>();
    let pks_serializable = pks
        .iter()
        .map(|pk: &G2Affine| (*pk).into())
        .collect::<Vec<G2AffineSerializable>>();
    GenKeysOutput {
        sks: sks_serializable,
        pks: pks_serializable,
    }
}

fn read_obj<T: DeserializeOwned>() -> Result<T, io::Error> {
    let mut raw = String::new();
    io::stdin().read_line(&mut raw)?;
    let deserializable: T = serde_json::from_str(raw.as_str())?;
    Ok(deserializable.into())
}

fn deserialize_vec<T: DeserializeOwned, S>(a: Vec<T>) -> Vec<S>
where
    T: Into<S>,
{
    a.into_iter().map(|elem: T| elem.into()).collect::<Vec<S>>()
}

fn main() -> Result<(), Box<dyn Error>> {
    // TODO: fix error handling
    let args = Cli::parse();
    let pairing_config = PairingConfig::new();

    match args.command {
        Commands::GenKeys { n } => {
            let all_keys = gen_keys(&pairing_config, n);
            println!("{}", serde_json::to_string(&all_keys)?);
            Ok(())
        }
        Commands::DealSecret { t } => {
            let pks = deserialize_vec::<G2AffineSerializable, G2Affine>(read_obj::<
                Vec<G2AffineSerializable>,
            >()?);
            let pvss_config = PVSSConfig::new(pairing_config, pks, t);
            let (ciphertext, secrets) = distribute_secret(&pvss_config).unwrap();
            let output = DealSecretOutput {
                ciphertext,
                secrets,
            };
            println!("{}", serde_json::to_string(&output)?);
            Ok(())
        }
        Commands::DecryptShare => {
            let input = read_obj::<DecryptShareInput>()?;
            let decrypted_share: G2AffineSerializable =
                decrypt_share(&input.ciphertext, &input.sk.into(), input.i)?.into();
            println!("{}", serde_json::to_string(&decrypted_share)?);
            Ok(())
        }
        Commands::CombineShares => {
            let input = read_obj::<Vec<CombineSharesInputElem>>()?;
            let (indices, decrypted_shares): (Vec<usize>, Vec<G2Affine>) = input
                .iter()
                .map(|elem| (elem.i, elem.share.into()))
                .unzip::<usize, G2Affine, Vec<usize>, Vec<G2Affine>>();
            let result: G2AffineSerializable = combine_shares(&decrypted_shares, &indices)?.into();
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
        Commands::VerifyCiphertext => {
            let input = read_obj::<VerifyCiphertextInput>()?;
            let pks = deserialize_vec::<G2AffineSerializable, G2Affine>(input.pks);
            println!(
                "{}",
                verify_ciphertext(
                    &PVSSConfig::new(pairing_config, pks, input.t),
                    &input.ciphertext
                )
                .is_ok()
            );
            Ok(())
        }
    }
}

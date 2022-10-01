use ark_bn254::{Fr, G2Affine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand};
use clap::{Parser, Subcommand};
use rand::thread_rng;
use std::{fs, path::Path};
use walkdir::WalkDir;

use cassiopeia::{
    committee::decrypt_share,
    dealer::distribute_secret,
    public::combine_shares,
    serialize::*,
    structs::{PVSSCiphertext, PVSSConfig, PairingConfig},
};

#[derive(Parser, Debug)]
#[command(author, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(arg_required_else_help = true)]
    GenKeys {
        n: usize,
        sk_dir: String,
        pk_file: String,
    },
    #[command(arg_required_else_help = true)]
    DealSecret {
        t: usize,
        pk_file: String,
        ciphertext_file: String,
        secrets_file: String,
    },
    #[command(arg_required_else_help = true)]
    DecryptShare {
        ciphertext_file: String,
        sk_file: String,
        i: usize,
        output_file: String,
    },
    #[command(arg_required_else_help = true)]
    CombineShares {
        shares_dir: String,
        output_file: String,
    },
}

fn gen_keys(pairing_config: &PairingConfig, n: usize) -> (Vec<Fr>, Vec<G2Affine>) {
    let mut rng = thread_rng();
    let sks = (0..n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let pks = sks
        .iter()
        .map(|sk| pairing_config.h.mul(sk.into_repr()).into_affine())
        .collect::<Vec<_>>();
    (sks, pks)
}

fn main() {
    let args = Cli::parse();
    let pairing_config = PairingConfig::new();

    match args.command {
        Commands::GenKeys { n, sk_dir, pk_file } => {
            let (sks, pks) = gen_keys(&pairing_config, n);
            let sks_serializable = sks
                .iter()
                .map(|sk: &Fr| (*sk).into())
                .collect::<Vec<FrSerializable>>();
            let pks_serializable = pks
                .iter()
                .map(|pk: &G2Affine| (*pk).into())
                .collect::<Vec<G2AffineSerializable>>();

            fs::create_dir_all(&sk_dir).unwrap();
            for (i, sk) in sks_serializable.iter().enumerate() {
                let sk_file = Path::new(&sk_dir.as_str()).join(i.to_string());
                fs::write(sk_file, serde_json::to_string(&sk).unwrap()).unwrap();
            }
            fs::write(pk_file, serde_json::to_string(&pks_serializable).unwrap()).unwrap();
        }
        Commands::DealSecret {
            t,
            pk_file,
            ciphertext_file,
            secrets_file,
        } => {
            let pks_raw = fs::read_to_string(pk_file).unwrap();
            let pks_serializable: Vec<G2AffineSerializable> =
                serde_json::from_str(pks_raw.as_str()).unwrap();
            let pks = pks_serializable
                .into_iter()
                .map(|pk: G2AffineSerializable| pk.into())
                .collect::<Vec<G2Affine>>();
            let pvss_config = PVSSConfig::new(pairing_config, pks, t);
            let (pvss_ciphertext, pvss_secrets) = distribute_secret(&pvss_config).unwrap();
            fs::write(
                ciphertext_file,
                serde_json::to_string(&pvss_ciphertext).unwrap(),
            )
            .unwrap();
            fs::write(secrets_file, serde_json::to_string(&pvss_secrets).unwrap()).unwrap();
        }
        Commands::DecryptShare {
            ciphertext_file,
            sk_file,
            i,
            output_file,
        } => {
            let ciphertext_raw = fs::read_to_string(ciphertext_file).unwrap();
            let ciphertext: PVSSCiphertext = serde_json::from_str(ciphertext_raw.as_str()).unwrap();

            let sk_raw = fs::read_to_string(sk_file).unwrap();
            let sk_serializable: FrSerializable = serde_json::from_str(sk_raw.as_str()).unwrap();
            let sk: Fr = sk_serializable.into();

            let decryption = decrypt_share(&ciphertext, &sk, i).unwrap();
            let decryption_serialized: G2AffineSerializable = decryption.into();
            fs::write(
                output_file,
                serde_json::to_string(&decryption_serialized).unwrap(),
            )
            .unwrap();
        }
        Commands::CombineShares {
            shares_dir,
            output_file,
        } => {
            let (indices, decrypted_shares): (Vec<usize>, Vec<G2Affine>) = WalkDir::new(shares_dir)
                .into_iter()
                .filter_map(|f| f.ok())
                .filter_map(|f| {
                    let file_name_str: String = f.file_name().to_str().unwrap().to_string();
                    if let Some(i) = file_name_str.parse::<usize>().ok() {
                        let share_raw = fs::read_to_string(f.path()).unwrap();
                        let share_serializable: G2AffineSerializable =
                            serde_json::from_str(share_raw.as_str()).unwrap();
                        let share: G2Affine = share_serializable.into();
                        return Some((i, share));
                    } else {
                        return None;
                    }
                }).unzip();
            let result = combine_shares(&decrypted_shares, &indices).unwrap();
            let result_serialized: G2AffineSerializable = result.into();
            fs::write(
                output_file,
                serde_json::to_string(&result_serialized).unwrap(),
            )
            .unwrap();
        }
    }
}

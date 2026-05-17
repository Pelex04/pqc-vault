//! pqc-vault — command-line interface for post-quantum cryptography
//!
//! Exposes ML-KEM and ML-DSA operations as a portable CLI tool usable
//! by any developer or sysadmin without writing Rust code.

use clap::{Parser, Subcommand, ValueEnum};
use pqc_vault::{
    dsa::DsaKeyPair,
    kem::KemKeyPair,
    pem::{
        dsa_public_key_from_pem, dsa_public_key_to_pem, kem_public_key_from_pem,
        kem_public_key_to_pem,
    },
    serial::EncryptedKeyBundle,
    SecurityLevel,
};
use std::fs;
use std::path::PathBuf;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "pqc-vault",
    about = "Post-quantum cryptography — ML-KEM (FIPS 203) and ML-DSA (FIPS 204)",
    version = env!("CARGO_PKG_VERSION"),
    long_about = "
pqc-vault provides quantum-safe key generation, key exchange, and digital
signatures using NIST-standardized algorithms. Private keys are stored
encrypted with AES-256-GCM, passphrase-derived via Argon2id.

ALGORITHMS
  ML-KEM (Kyber)     Key encapsulation — replaces RSA/ECDH key exchange
  ML-DSA (Dilithium) Digital signatures — replaces RSA/ECDSA signatures

SECURITY LEVELS
  1   Kyber512  / Dilithium2  ~AES-128  Constrained devices
  3   Kyber768  / Dilithium3  ~AES-192  Recommended default
  5   Kyber1024 / Dilithium5  ~AES-256  Long-term secrets
"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new key pair and save encrypted to disk
    Keygen {
        /// Algorithm to use
        #[arg(long, value_enum)]
        algo: Algo,

        /// Security level (1, 3, or 5)
        #[arg(long, default_value = "3")]
        level: u8,

        /// Output path for the encrypted private key (JSON)
        #[arg(long)]
        out: PathBuf,

        /// Also write the public key as PEM to <out>.pub
        #[arg(long, default_value = "true")]
        pub_key: bool,
    },

    /// Encapsulate a shared secret to a KEM public key
    Encapsulate {
        /// Path to the recipient's public key PEM file
        #[arg(long)]
        key: PathBuf,

        /// Output path for the ciphertext (hex)
        #[arg(long)]
        ct_out: PathBuf,

        /// Output path for the shared secret (hex)
        #[arg(long)]
        secret_out: PathBuf,
    },

    /// Decapsulate a ciphertext using a KEM private key
    Decapsulate {
        /// Path to the encrypted private key bundle (JSON)
        #[arg(long)]
        key: PathBuf,

        /// Path to the ciphertext file (hex)
        #[arg(long)]
        ct: PathBuf,

        /// Output path for the recovered shared secret (hex)
        #[arg(long)]
        secret_out: PathBuf,
    },

    /// Sign a file using a DSA private key
    Sign {
        /// Path to the encrypted private key bundle (JSON)
        #[arg(long)]
        key: PathBuf,

        /// File to sign
        #[arg(long)]
        file: PathBuf,

        /// Output path for the detached signature (hex)
        #[arg(long)]
        sig_out: PathBuf,
    },

    /// Verify a file signature using a DSA public key
    Verify {
        /// Path to the signer's public key PEM file
        #[arg(long)]
        key: PathBuf,

        /// File that was signed
        #[arg(long)]
        file: PathBuf,

        /// Path to the detached signature (hex)
        #[arg(long)]
        sig: PathBuf,
    },

    /// Display information about an encrypted key bundle
    Inspect {
        /// Path to the encrypted key bundle (JSON)
        #[arg(long)]
        key: PathBuf,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum Algo {
    /// ML-KEM (Kyber) — key encapsulation
    Kem,
    /// ML-DSA (Dilithium) — digital signatures
    Dsa,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli.command) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Keygen {
            algo,
            level,
            out,
            pub_key,
        } => cmd_keygen(algo, level, out, pub_key),
        Command::Encapsulate {
            key,
            ct_out,
            secret_out,
        } => cmd_encapsulate(key, ct_out, secret_out),
        Command::Decapsulate {
            key,
            ct,
            secret_out,
        } => cmd_decapsulate(key, ct, secret_out),
        Command::Sign { key, file, sig_out } => cmd_sign(key, file, sig_out),
        Command::Verify { key, file, sig } => cmd_verify(key, file, sig),
        Command::Inspect { key } => cmd_inspect(key),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

fn cmd_keygen(
    algo: Algo,
    level: u8,
    out: PathBuf,
    write_pub: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let level = parse_level(level)?;
    let passphrase = prompt_new_passphrase()?;

    match algo {
        Algo::Kem => {
            eprint!(
                "Generating ML-KEM key pair (level {})... ",
                level_num(level)
            );
            let kp = KemKeyPair::generate(level)?;
            let pub_key = kp.public_key();
            let bundle = EncryptedKeyBundle::seal_kem(&kp, passphrase.as_bytes())?;
            fs::write(&out, bundle.to_json())?;
            eprintln!("done");
            eprintln!("Private key written to: {}", out.display());

            if write_pub {
                let pub_path = pub_path(&out);
                fs::write(&pub_path, kem_public_key_to_pem(&pub_key))?;
                eprintln!("Public key written to:  {}", pub_path.display());
            }
        }
        Algo::Dsa => {
            eprint!(
                "Generating ML-DSA key pair (level {})... ",
                level_num(level)
            );
            let kp = DsaKeyPair::generate(level)?;
            let pub_key = kp.public_key();
            let bundle = EncryptedKeyBundle::seal_dsa(&kp, passphrase.as_bytes())?;
            fs::write(&out, bundle.to_json())?;
            eprintln!("done");
            eprintln!("Private key written to: {}", out.display());

            if write_pub {
                let pub_path = pub_path(&out);
                fs::write(&pub_path, dsa_public_key_to_pem(&pub_key))?;
                eprintln!("Public key written to:  {}", pub_path.display());
            }
        }
    }

    Ok(())
}

fn cmd_encapsulate(
    key_path: PathBuf,
    ct_out: PathBuf,
    secret_out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let pem = fs::read_to_string(&key_path)?;

    // Try KEM first
    if pem.contains("ML-KEM") {
        let pub_key = kem_public_key_from_pem(&pem)?;
        let (ct, secret) = KemKeyPair::encapsulate(&pub_key)?;
        fs::write(&ct_out, hex::encode(&ct))?;
        fs::write(&secret_out, hex::encode(secret.as_bytes()))?;
        eprintln!("Ciphertext written to:    {}", ct_out.display());
        eprintln!("Shared secret written to: {}", secret_out.display());
        eprintln!("Shared secret is {} bytes.", secret.as_bytes().len());
    } else {
        return Err("Key file does not contain an ML-KEM public key".into());
    }

    Ok(())
}

fn cmd_decapsulate(
    key_path: PathBuf,
    ct_path: PathBuf,
    secret_out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = fs::read_to_string(&key_path)?;
    let passphrase = prompt_passphrase()?;
    let bundle = EncryptedKeyBundle::from_json(&json)?;
    let kp = bundle
        .unseal_kem(passphrase.as_bytes())
        .map_err(|_| "Decryption failed — wrong passphrase or corrupted key file")?;

    let ct_hex = fs::read_to_string(&ct_path)?;
    let ct = hex::decode(ct_hex.trim())?;
    let secret = kp.decapsulate(&ct)?;

    fs::write(&secret_out, hex::encode(secret.as_bytes()))?;
    eprintln!("Shared secret written to: {}", secret_out.display());
    eprintln!("Shared secret is {} bytes.", secret.as_bytes().len());

    Ok(())
}

fn cmd_sign(
    key_path: PathBuf,
    file_path: PathBuf,
    sig_out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = fs::read_to_string(&key_path)?;
    let passphrase = prompt_passphrase()?;
    let bundle = EncryptedKeyBundle::from_json(&json)?;
    let kp = bundle
        .unseal_dsa(passphrase.as_bytes())
        .map_err(|_| "Decryption failed — wrong passphrase or corrupted key file")?;

    let message = fs::read(&file_path)?;
    let signature = kp.sign(&message)?;

    fs::write(&sig_out, hex::encode(signature.as_slice()))?;
    eprintln!("Signed {} ({} bytes)", file_path.display(), message.len());
    eprintln!("Signature written to: {}", sig_out.display());

    Ok(())
}

fn cmd_verify(
    key_path: PathBuf,
    file_path: PathBuf,
    sig_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let pem = fs::read_to_string(&key_path)?;

    if !pem.contains("ML-DSA") {
        return Err("Key file does not contain an ML-DSA public key".into());
    }

    let pub_key = dsa_public_key_from_pem(&pem)?;
    let message = fs::read(&file_path)?;
    let sig_hex = fs::read_to_string(&sig_path)?;
    let sig = hex::decode(sig_hex.trim())?;

    match DsaKeyPair::verify_with_typed_key(&pub_key, &message, &sig) {
        Ok(()) => {
            println!("Signature valid.");
            println!("  File:   {}", file_path.display());
            println!("  Key:    {}", key_path.display());
        }
        Err(_) => {
            eprintln!("Signature INVALID.");
            eprintln!("  The file may have been modified, or the wrong key was used.");
            std::process::exit(2);
        }
    }

    Ok(())
}

fn cmd_inspect(key_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&key_path)?)?;

    let kind = json["kind"].as_str().unwrap_or("unknown");
    let level = json["level"].as_u64().unwrap_or(0);

    let algo = match kind {
        "kem" => "ML-KEM (Kyber)",
        "dsa" => "ML-DSA (Dilithium)",
        _ => "Unknown",
    };
    let variant = match (kind, level) {
        ("kem", 1) => "Kyber512  (~AES-128)",
        ("kem", 3) => "Kyber768  (~AES-192)",
        ("kem", 5) => "Kyber1024 (~AES-256)",
        ("dsa", 1) => "Dilithium2 (~AES-128)",
        ("dsa", 3) => "Dilithium3 (~AES-192)",
        ("dsa", 5) => "Dilithium5 (~AES-256)",
        _ => "Unknown",
    };

    println!("Key bundle: {}", key_path.display());
    println!("  Algorithm:      {}", algo);
    println!("  Variant:        {}", variant);
    println!("  Security level: {}", level);
    println!("  Encryption:     AES-256-GCM");
    println!("  KDF:            Argon2id (64MB, 3 iterations)");
    println!("  Format:         Encrypted JSON bundle");

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_level(n: u8) -> Result<SecurityLevel, Box<dyn std::error::Error>> {
    match n {
        1 => Ok(SecurityLevel::Level1),
        3 => Ok(SecurityLevel::Level3),
        5 => Ok(SecurityLevel::Level5),
        _ => Err(format!("Invalid security level: {}. Must be 1, 3, or 5.", n).into()),
    }
}

fn level_num(level: SecurityLevel) -> u8 {
    match level {
        SecurityLevel::Level1 => 1,
        SecurityLevel::Level3 => 3,
        SecurityLevel::Level5 => 5,
    }
}

fn pub_path(key_path: &PathBuf) -> PathBuf {
    let mut p = key_path.clone();
    let name = p
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    p.set_file_name(format!("{}.pub", name));
    p
}

fn prompt_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    let pass = rpassword::prompt_password("Passphrase: ")?;
    if pass.is_empty() {
        return Err("Passphrase cannot be empty".into());
    }
    Ok(pass)
}

fn prompt_new_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    let pass = rpassword::prompt_password("New passphrase: ")?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if pass.is_empty() {
        return Err("Passphrase cannot be empty".into());
    }
    if pass != confirm {
        return Err("Passphrases do not match".into());
    }
    Ok(pass)
}

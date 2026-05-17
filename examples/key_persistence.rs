//! Example: saving and loading keys securely
//!
//! Demonstrates the full key persistence lifecycle: generate, encrypt,
//! save to disk, load from disk, decrypt, and use.
//!
//! Run with: cargo run --example key_persistence

use pqc_vault::{kem::KemKeyPair, serial::EncryptedKeyBundle, SecurityLevel};
use std::fs;

fn main() {
    println!("=== Key Persistence with AES-256-GCM + Argon2id ===\n");

    let key_file = "/tmp/pqc_vault_example.key";
    let passphrase = b"example-passphrase-change-in-production";

    // Step 1: Generate a key pair
    println!("Generating ML-KEM key pair...");
    let kp = KemKeyPair::generate(SecurityLevel::Level3).expect("key generation failed");
    let pub_key = kp.public_key();
    println!(
        "Public key: {}... ({} bytes)",
        &pub_key.to_hex()[..16],
        pub_key.as_bytes().len()
    );

    // Step 2: Encrypt and save to disk
    println!("\nEncrypting private key with AES-256-GCM (Argon2id KDF)...");
    let bundle = EncryptedKeyBundle::seal_kem(&kp, passphrase).expect("sealing failed");
    let json = bundle.to_json();
    fs::write(key_file, &json).expect("write failed");
    println!("Private key saved to: {}", key_file);
    println!("Saved {} bytes (encrypted)", json.len());

    // The key is now on disk. Drop everything from memory.
    drop(kp);
    drop(bundle);

    // Step 3: Load from disk and decrypt
    println!("\nLoading key from disk and decrypting...");
    let loaded_json = fs::read_to_string(key_file).expect("read failed");
    let loaded_bundle = EncryptedKeyBundle::from_json(&loaded_json).expect("JSON parse failed");
    let restored = loaded_bundle
        .unseal_kem(passphrase)
        .expect("decryption failed — wrong passphrase?");
    println!("Key restored successfully.");
    println!(
        "Public key matches: {}",
        restored.public_key().as_bytes() == pub_key.as_bytes()
    );

    // Step 4: Verify the restored key works
    println!("\nVerifying restored key with a test encapsulation...");
    let (ct, bob_secret) =
        KemKeyPair::encapsulate(&restored.public_key()).expect("encapsulation failed");
    let alice_secret = restored.decapsulate(&ct).expect("decapsulation failed");
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    println!("Shared secret matches. Restored key is fully functional.");

    // Clean up
    fs::remove_file(key_file).ok();
    println!("\nKey file removed. In production:");
    println!("  - Use a secrets manager (HashiCorp Vault, AWS Secrets Manager)");
    println!("  - Or HSM where keys never leave hardware");
    println!("  - Never store the passphrase alongside the key file");
}

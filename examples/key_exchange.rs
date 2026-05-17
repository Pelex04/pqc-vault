//! Example: quantum-safe key exchange between Alice and Bob
//!
//! Demonstrates a complete ML-KEM key exchange, producing a shared secret
//! that both parties can use to derive a symmetric encryption key.
//!
//! Run with: cargo run --example key_exchange

use pqc_vault::{kem::KemKeyPair, utils::ct_eq, SecurityLevel};

fn main() {
    println!("=== ML-KEM Key Exchange (NIST FIPS 203) ===\n");

    // Step 1: Alice generates a key pair and shares her public key
    println!("[Alice] Generating ML-KEM key pair at Level 3 (Kyber768)...");
    let alice = KemKeyPair::generate(SecurityLevel::Level3).expect("key generation failed");
    let alice_pub = alice.public_key();
    println!(
        "[Alice] Public key: {}...{} ({} bytes)",
        &alice_pub.to_hex()[..16],
        &alice_pub.to_hex()[alice_pub.to_hex().len() - 8..],
        alice_pub.as_bytes().len()
    );

    // Step 2: Bob encapsulates a shared secret to Alice's public key
    println!("\n[Bob]   Encapsulating shared secret to Alice's public key...");
    let (ciphertext, bob_secret) =
        KemKeyPair::encapsulate(&alice_pub).expect("encapsulation failed");
    println!(
        "[Bob]   Ciphertext: {}...{} ({} bytes)",
        hex::encode(&ciphertext[..8]),
        hex::encode(&ciphertext[ciphertext.len() - 4..]),
        ciphertext.len()
    );
    println!(
        "[Bob]   Shared secret: {}... ({} bytes)",
        hex::encode(&bob_secret.as_bytes()[..8]),
        bob_secret.as_bytes().len()
    );

    // Step 3: Alice decapsulates the ciphertext to recover the shared secret
    println!("\n[Alice] Decapsulating ciphertext...");
    let alice_secret = alice
        .decapsulate(&ciphertext)
        .expect("decapsulation failed");
    println!(
        "[Alice] Shared secret: {}... ({} bytes)",
        hex::encode(&alice_secret.as_bytes()[..8]),
        alice_secret.as_bytes().len()
    );

    // Step 4: Verify both secrets match
    println!("\n[Check] Comparing secrets (constant-time)...");
    assert!(
        ct_eq(alice_secret.as_bytes(), bob_secret.as_bytes()),
        "Shared secrets do not match — this should never happen"
    );
    println!("[Check] Secrets match. Both parties now share a 256-bit secret.");
    println!("\nAlice and Bob can now use this shared secret as input to a KDF");
    println!("(e.g. HKDF) to derive symmetric encryption keys for their session.");
    println!("\nAn attacker who intercepted the ciphertext cannot recover the");
    println!("shared secret without Alice's private key — even with a quantum computer.");
}

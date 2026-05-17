//! Example: hybrid X25519 + ML-KEM key exchange
//!
//! Demonstrates a hybrid key exchange that is secure against both classical
//! and quantum attackers. An adversary must break both X25519 and Kyber
//! to recover the shared secret.
//!
//! Run with: cargo run --example hybrid_exchange

use pqc_vault::{hybrid::HybridKeyPair, SecurityLevel};

fn main() {
    println!("=== Hybrid X25519 + ML-KEM Key Exchange ===\n");
    println!("This exchange is secure against classical AND quantum attackers.");
    println!("An attacker must break BOTH X25519 and Kyber to recover the secret.\n");

    // Step 1: Alice generates a hybrid key pair
    println!("[Alice] Generating hybrid key pair (X25519 + Kyber768)...");
    let alice = HybridKeyPair::generate(SecurityLevel::Level3).expect("key generation failed");
    let alice_pub = alice.public_key();
    println!(
        "[Alice] X25519 component: {}... ({} bytes)",
        hex::encode(&alice_pub.x25519_bytes()[..8]),
        alice_pub.x25519_bytes().len()
    );
    println!(
        "[Alice] Kyber component:  {}... ({} bytes)",
        hex::encode(&alice_pub.kyber_key().as_bytes()[..8]),
        alice_pub.kyber_key().as_bytes().len()
    );

    // Step 2: Bob encapsulates using Alice's public key
    println!("\n[Bob]   Encapsulating hybrid shared secret...");
    let (ciphertext, bob_secret) =
        HybridKeyPair::encapsulate(&alice_pub).expect("encapsulation failed");
    println!(
        "[Bob]   X25519 ephemeral: {}... ({} bytes)",
        hex::encode(&ciphertext.x25519_ephemeral.as_bytes()[..8]),
        ciphertext.x25519_ephemeral.as_bytes().len()
    );
    println!(
        "[Bob]   Kyber ciphertext: {}... ({} bytes)",
        hex::encode(&ciphertext.kyber_ct[..8]),
        ciphertext.kyber_ct.len()
    );
    println!(
        "[Bob]   Combined secret (HKDF output): {}... ({} bytes)",
        hex::encode(&bob_secret[..8]),
        bob_secret.len()
    );

    // Step 3: Alice decapsulates
    println!("\n[Alice] Decapsulating hybrid ciphertext...");
    let alice_secret = alice
        .decapsulate(&ciphertext)
        .expect("decapsulation failed");
    println!(
        "[Alice] Combined secret (HKDF output): {}... ({} bytes)",
        hex::encode(&alice_secret[..8]),
        alice_secret.len()
    );

    // Step 4: Verify
    assert_eq!(
        alice_secret.as_slice(),
        bob_secret.as_slice(),
        "Hybrid secrets do not match"
    );
    println!("\n[Check] Secrets match. Both parties share a 256-bit hybrid secret.");
    println!("\nCombiner: HKDF-Extract+Expand(x25519_shared || kyber_shared)");
    println!("Domain:   'pqc_vault hybrid v1'");
    println!("Output:   32 bytes (256 bits)");
    println!("\nIf X25519 is broken by a quantum computer: Kyber provides full security.");
    println!("If Kyber has an unknown weakness:           X25519 provides full security.");
}

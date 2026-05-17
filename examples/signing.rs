//! Example: quantum-safe document signing and verification
//!
//! Demonstrates ML-DSA signing of a document and verification by a third party
//! who holds only the signer's public key.
//!
//! Run with: cargo run --example signing

use pqc_vault::{
    dsa::DsaKeyPair,
    pem::{dsa_public_key_from_pem, dsa_public_key_to_pem},
    SecurityLevel,
};

fn main() {
    println!("=== ML-DSA Digital Signatures (NIST FIPS 204) ===\n");

    // Step 1: Signer generates a key pair
    println!("[Signer]   Generating ML-DSA key pair at Level 3 (Dilithium3)...");
    let signer = DsaKeyPair::generate(SecurityLevel::Level3).expect("key generation failed");
    let pub_key = signer.public_key();
    println!(
        "[Signer]   Public key: {}...{} ({} bytes)",
        &pub_key.to_hex()[..16],
        &pub_key.to_hex()[pub_key.to_hex().len() - 8..],
        pub_key.as_bytes().len()
    );

    // Step 2: Signer exports public key as PEM and distributes it
    println!("\n[Signer]   Exporting public key as PEM...");
    let pem = dsa_public_key_to_pem(&pub_key);
    println!("{}", pem);

    // Step 3: Sign a message
    let document = b"I authorise a transfer of $50,000 to account 9872-001. \
                     Date: 2026-05-16. Reference: INV-4492.";
    println!("[Signer]   Signing document ({} bytes)...", document.len());
    let signature = signer.sign(document).expect("signing failed");
    println!(
        "[Signer]   Signature: {}...{} ({} bytes)",
        hex::encode(&signature[..8]),
        hex::encode(&signature[signature.len() - 4..]),
        signature.len()
    );

    // Step 4: Verifier receives the PEM public key, document, and signature
    println!("\n[Verifier] Importing signer public key from PEM...");
    let verifier_pub = dsa_public_key_from_pem(&pem).expect("PEM import failed");

    println!("[Verifier] Verifying signature...");
    match DsaKeyPair::verify_with_typed_key(&verifier_pub, document, &signature) {
        Ok(()) => println!("[Verifier] Signature VALID. Document is authentic."),
        Err(e) => println!("[Verifier] Signature INVALID: {}", e),
    }

    // Step 5: Show that tampering is detected
    println!("\n[Attacker] Tampering with document...");
    let tampered = b"I authorise a transfer of $999,999 to account 9872-001. \
                     Date: 2026-05-16. Reference: INV-4492.";
    match DsaKeyPair::verify_with_typed_key(&verifier_pub, tampered, &signature) {
        Ok(()) => println!("[Attacker] Signature valid (this should never happen)"),
        Err(_) => println!("[Attacker] Signature INVALID. Tampering detected."),
    }

    println!("\nThe signature binds the signer's identity to the exact document.");
    println!("Any modification — even a single byte — invalidates the signature.");
    println!("An attacker cannot forge a valid signature without the private key,");
    println!("even with a quantum computer.");
}

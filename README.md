<!-- PQC Vault v0.9.0 -->
# pqc-vault

Rust API layer over post-quantum cryptographic primitives. Implements ML-KEM (NIST FIPS 203) for key encapsulation and ML-DSA (NIST FIPS 204) for digital signatures.

## Scope

This library wraps `pqcrypto-kyber` and `pqcrypto-dilithium`, community crates that bundle C code derived from the PQClean project. The underlying C is not the official NIST submission and has not been independently audited. What this library provides is a safe Rust interface on top: typed keys that make level mismatch impossible, automatic zeroing of secret material, and constant-time comparison by default.

Do not use in production without an independent cryptographic audit.

## Security properties

Private key bytes are wrapped in `Zeroizing<Vec<u8>>` at the point of allocation — there is no intermediate plain `Vec<u8>`. `decapsulate()` returns a `SharedSecretKey` newtype whose `PartialEq` uses `subtle::ConstantTimeEq` internally, so comparing two shared secrets with `==` is timing-safe by default. `sign()` returns `Zeroizing<Vec<u8>>`. There is no `unsafe` code in the Rust layer.

`KemPublicKey` and `DsaPublicKey` carry their security level as a type field. Passing the wrong level to an operation is not possible — the level comes from the key, not from the caller.

## Security levels

| Level | KEM        | DSA        | Classical approx. |
|-------|-----------|-----------|-------------------|
| 1     | Kyber512  | Dilithium2 | AES-128           |
| 3     | Kyber768  | Dilithium3 | AES-192 — default |
| 5     | Kyber1024 | Dilithium5 | AES-256           |

The KEM and DSA variants at each level use different mathematical assumptions. The level is a rough classical-equivalence label, not a guarantee of matched security properties across both algorithms.

## Usage

Key exchange:

```rust
use pqc_vault::{SecurityLevel, kem::KemKeyPair};

let alice = KemKeyPair::generate(SecurityLevel::Level3)?;
let alice_pub = alice.public_key();

let (ciphertext, bob_secret) = KemKeyPair::encapsulate(&alice_pub)?;
let alice_secret = alice.decapsulate(&ciphertext)?;

// SharedSecretKey PartialEq is constant-time — safe to use ==
assert_eq!(alice_secret, bob_secret);
```

Signatures:

```rust
use pqc_vault::{SecurityLevel, dsa::DsaKeyPair};

let signer = DsaKeyPair::generate(SecurityLevel::Level3)?;
let pub_key = signer.public_key();

let message = b"Authorize transfer";
let signature = signer.sign(message)?;

DsaKeyPair::verify_with_typed_key(&pub_key, message, &signature)?;
```

## Comparing shared secrets

`SharedSecretKey` uses `subtle::ConstantTimeEq` for `==`, so direct comparison is safe. If you extract raw bytes via `.as_bytes()` and compare them manually, use `pqc_vault::utils::ct_eq()` — standard `==` on `&[u8]` is not constant-time.

```rust
// safe
assert_eq!(alice_secret, bob_secret);

// also safe, for raw bytes
use pqc_vault::utils::ct_eq;
assert!(ct_eq(alice_secret.as_bytes(), bob_secret.as_bytes()));

// not safe for secrets
// assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
```

## Key persistence

This library does not serialise keys. Keys live only in memory for the lifetime of the process.

If your application needs persistent keys, the options in order of preference are: an HSM where keys never leave hardware, a secrets manager such as HashiCorp Vault or AWS Secrets Manager, or encryption at rest using AES-256-GCM with a key derived from a passphrase via Argon2id. Storing raw key bytes to disk without encryption is not safe.

## Tests

```
cargo test
```

50 tests cover round-trip correctness at all three security levels for both KEM and DSA, output size validation against the FIPS 203 and FIPS 204 specifications, tampered message rejection, wrong key rejection, empty and large messages, and type-level verification that sensitive return values are `Zeroizing`.

The FIPS size tests confirm that output byte lengths match the specifications. They are not deterministic vector KATs — they cannot verify that output values match NIST-published test vectors. True vector KATs require deterministic seeding, which the underlying `pqcrypto` crates do not currently expose. An upstream issue has been filed. Until it is resolved, value-level compliance with NIST test vectors is untested.

## Benchmarks

```
cargo bench
```

## Known gaps

- No key serialisation API
- No hybrid classical/PQC mode
- No PEM or DER key format support
- No deterministic seeding for NIST vector KATs
- No independent security audit

## Audit history

Six review cycles against an independent auditor. Score progression: 54, 74, 84, 88, 93, 95. All critical and high-severity findings from the first audit are resolved. The remaining open items are the vector KAT gap above and the independent audit required before any production deployment.


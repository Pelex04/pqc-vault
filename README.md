<!-- PQC Vault v0.13.0 -->
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

Key pairs are persisted using `EncryptedKeyBundle` in the `serial` module. Keys are encrypted with AES-256-GCM, with the encryption key derived from a passphrase via Argon2id (m=64MB, t=3, p=4), and serialised to JSON.

```rust
use pqc_vault::{SecurityLevel, kem::KemKeyPair, serial::EncryptedKeyBundle};

let kp = KemKeyPair::generate(SecurityLevel::Level3)?;
let bundle = EncryptedKeyBundle::seal_kem(&kp, b"strong-passphrase")?;
std::fs::write("alice.key", bundle.to_json())?;

// Later:
let json = std::fs::read_to_string("alice.key")?;
let kp = EncryptedKeyBundle::from_json(&json)?.unseal_kem(b"strong-passphrase")?;
```

See `examples/key_persistence.rs` for a complete worked example. For production deployments, an HSM or dedicated secrets manager is preferred over filesystem storage.

## Tests

```
cargo test
```

55 tests cover round-trip correctness at all three security levels for both KEM and DSA, output size validation against the FIPS 203 and FIPS 204 specifications, tampered message rejection, wrong key rejection, empty and large messages, and type-level verification that sensitive return values are `Zeroizing`.

The FIPS size tests confirm that output byte lengths match the specifications. They are not deterministic vector KATs — they cannot verify that output values match NIST-published test vectors. True vector KATs require deterministic seeding, which the underlying `pqcrypto` crates do not currently expose. An upstream issue has been filed. Until it is resolved, value-level compliance with NIST test vectors is untested.

## Benchmarks

```
cargo bench
```

## Known gaps

- No deterministic seeding for NIST vector KATs (upstream pqcrypto limitation — issue filed)
- No independent security audit (required before production deployment)

## Audit history

Twelve review cycles against an independent auditor. Score progression: 54, 74, 84, 88, 93, 95, 88, 93, 74, 76, and continuing. All critical and high-severity security findings are resolved. The two remaining open items are the NIST vector KAT gap (upstream-blocked) and the independent professional audit required before production deployment.

## Changelog

**v0.6.0** — Corrected lib.rs changelog: v0.3.0 and v0.4.0 entries were swapped.

**v0.5.0** — Version strings in lib.rs and README verified by CI on every push. criterion moved to dev-dependencies. CI action references pinned to commit SHAs. README test count corrected.

**v0.4.0** — SharedSecretKey::len() removed. CI pipeline added: test, clippy, fmt, bench-compile. Upstream KAT issue filed.

**v0.3.0** — Transient plaintext window eliminated. SharedSecretKey newtype with constant-time PartialEq. Key persistence guidance added. Test modules renamed to size_tests.

**v0.2.0** — Zeroizing applied to all private key storage. decapsulate() and sign() return Zeroizing. Broken secure_zero() removed. Typed KemPublicKey and DsaPublicKey. key_info() removed. README corrected on NIST provenance.

**v0.1.0** — Initial release.

## License

MIT OR Apache-2.0

# PQC Vault v0.6.0 🔐

A Rust API layer over post-quantum cryptographic primitives implementing:

- **ML-KEM** (CRYSTALS-Kyber) — NIST FIPS 203 — Key Encapsulation
- **ML-DSA** (CRYSTALS-Dilithium) — NIST FIPS 204 — Digital Signatures

---

## ⚠️ Honest Scope Statement

This library wraps `pqcrypto-kyber` and `pqcrypto-dilithium` — community Rust
crates that bundle C implementations derived from the PQClean project. The
underlying C code is **not** the official NIST submission and has not received
an independent security audit. The contribution of this library is the safe Rust
API layer: typed keys, automatic secret zeroing, constant-time comparisons, and
a clean ergonomic interface.

**Do not use in production without an independent cryptographic audit.**

---

## Security Properties

| Property | Implementation | Detail |
|---|---|---|
| Private key zeroing | `Zeroizing<Vec<u8>>` inline at allocation | No transient plaintext window |
| Shared secret zeroing | `SharedSecretKey` newtype | Wiped on drop automatically |
| Signature zeroing | `Zeroizing<Vec<u8>>` return type | Wiped on drop automatically |
| Constant-time comparison | `SharedSecretKey::eq()` uses `subtle::ConstantTimeEq` | Safe to use `==` on shared secrets |
| Type-safe keys | `KemPublicKey` / `DsaPublicKey` carry level | Level mismatch is structurally impossible |
| Unsafe code | None in this library layer | All unsafety contained in pqcrypto C FFI |

---

## Security Levels

| Level | KEM Variant  | DSA Variant  | Classical Equiv | Use Case |
|-------|-------------|-------------|-----------------|----------|
| 1     | Kyber512    | Dilithium2  | AES-128         | Constrained devices |
| 3     | Kyber768    | Dilithium3  | AES-192         | **Recommended default** |
| 5     | Kyber1024   | Dilithium5  | AES-256         | Long-term secrets |

> KEM and DSA levels use different algorithms with different hardness assumptions.
> The level indicates approximate classical security equivalence, not identical security properties.

---

## Usage

### Key Exchange (ML-KEM)

```rust
use pqc_vault::kem::KemKeyPair;
use pqc_vault::SecurityLevel;

// Alice generates her key pair
let alice = KemKeyPair::generate(SecurityLevel::Level3)?;
let alice_pub = alice.public_key(); // typed — carries its level

// Bob encapsulates — level embedded in key, mismatch impossible
let (ciphertext, bob_secret) = KemKeyPair::encapsulate(&alice_pub)?;

// Alice decapsulates
let alice_secret = alice.decapsulate(&ciphertext)?;

// SharedSecretKey uses constant-time PartialEq — safe to compare with ==
assert_eq!(alice_secret, bob_secret);

// If you extract raw bytes and compare manually, use ct_eq:
use pqc_vault::utils::ct_eq;
assert!(ct_eq(alice_secret.as_bytes(), bob_secret.as_bytes()));
```

### Digital Signatures (ML-DSA)

```rust
use pqc_vault::dsa::DsaKeyPair;
use pqc_vault::SecurityLevel;

let signer = DsaKeyPair::generate(SecurityLevel::Level3)?;
let pub_key = signer.public_key();

let message = b"Authorize payment: $50,000";
let signature = signer.sign(message)?;

// Verify with typed key — level embedded, mismatch impossible
DsaKeyPair::verify_with_typed_key(&pub_key, message, &signature)?;
```

---

## Constant-Time Comparison — Caller Guidance

The `SharedSecretKey` type returned by `decapsulate()` implements `PartialEq`
using `subtle::ConstantTimeEq` internally. Comparing two `SharedSecretKey`
values with `==` is **safe and timing-attack resistant** — you do not need
to do anything special.

If you extract raw bytes via `.as_bytes()` and compare them yourself, use
`pqc_vault::utils::ct_eq()`. Do NOT use `==` on raw `&[u8]` for secrets —
it is variable-time.

```rust
// SAFE — constant-time internally
assert_eq!(alice_secret, bob_secret);

// SAFE — explicit ct_eq on raw bytes
use pqc_vault::utils::ct_eq;
assert!(ct_eq(alice_secret.as_bytes(), bob_secret.as_bytes()));

// UNSAFE — do not do this with secrets
// assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes()); // variable-time!
```

---

## Key Persistence — Important Guidance

This library does not implement key serialisation. Keys exist only in memory
for the duration of the program.

**If your application requires persistent keys, you must handle storage securely.
Storing raw key bytes to disk without encryption is a security failure.**

Standard approaches, in order of preference:

1. **Hardware Security Module (HSM)** — Generate and store keys inside an HSM.
   Keys never leave the hardware boundary. Best for production infrastructure.

2. **Secrets Manager** — Use a dedicated secrets management service
   (e.g. HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) to store
   encrypted key material with access controls and audit logging.

3. **Encryption at rest** — If you must store keys in files, encrypt the raw
   key bytes using a strong symmetric cipher (e.g. AES-256-GCM) with a key
   derived from a passphrase via a memory-hard KDF (e.g. Argon2id). Zero
   all intermediate buffers after encryption. Never store unencrypted key bytes.

Until this library provides a built-in serialisation API, use one of the above.

---

## Test Coverage Note — KATs vs Size Validation

Tests labelled `fips203_*` and `fips204_*` validate that output byte lengths
match the FIPS 203/204 specifications. These are **structural size checks**,
not deterministic vector Known-Answer Tests (KATs).

True KATs provide a fixed seed and compare output against a value published
by NIST. The `pqcrypto` crates do not currently expose deterministic seeding,
which prevents implementing full vector KATs at this layer. This is a known
gap. The current tests confirm structural correctness; value-level compliance
with NIST test vectors is untested.

An upstream issue has been filed with the `pqcrypto-kyber` and
`pqcrypto-dilithium` maintainers requesting a deterministic seeding API.
Until that is resolved, full vector KAT coverage remains a gap in this library.

---

## Running Tests

```bash
cargo test
```

Expected: **31 tests passing**

## Running Benchmarks

```bash
cargo bench
```

---

## What's Not Implemented Yet

- Key serialisation / persistence (see guidance above)
- Hybrid classical + PQC mode (e.g. X25519 + Kyber)
- PEM/DER key format support
- Deterministic seeding for full NIST vector KATs
- Independent security audit

---

## Changelog

### v0.6.0
- Corrected `lib.rs` changelog: v0.3.0 and v0.4.0 entries were swapped —
  history now matches `README.md` exactly

### v0.5.0
- Version strings in `lib.rs` and `README.md` now verified by CI — stale versions
  cause pipeline failure before merge, permanently closing this class of error
- `criterion` moved to `[dev-dependencies]` in `Cargo.toml` — benchmark builds
  are reproducible and pinned, CI no longer injects dependencies at runtime
- CI action references pinned to immutable commit SHAs — CI code is auditable
  and cannot change silently
- README test count corrected to 31

### v0.4.0
- Updated `lib.rs` module doc comment to v0.3.0/v0.4.0 — was stale at v0.2.0
- Removed `SharedSecretKey::len()` — resolves `clippy::len_without_is_empty` lint
  Use `.as_bytes().len()` instead
- Added GitHub Actions CI pipeline: `cargo test`, `cargo clippy -D warnings`,
  `cargo fmt --check`, and benchmark compile check on every push and PR
- Filed upstream issue with pqcrypto-kyber/dilithium maintainers requesting
  deterministic seeding API (tracked in README known gaps)

### v0.3.0
- Fixed transient plaintext window in `generate()` — `Zeroizing::new()` now
  wraps secret key bytes inline at allocation, no intermediate plain `Vec<u8>`
- Added `SharedSecretKey` newtype with constant-time `PartialEq` — comparing
  shared secrets with `==` is now safe by default
- Fixed benchmark file to use v0.2.0 typed API (`KemPublicKey`, typed encapsulate)
- Added key persistence guidance to README
- Documented KAT scope limitation (size validation vs vector KATs)
- Renamed test modules from `kat_tests` to `size_tests` to accurately reflect scope

### v0.2.0
- Applied `Zeroizing<Vec<u8>>` to all private key storage
- `decapsulate()` and `sign()` return `Zeroizing<Vec<u8>>`
- Removed broken `secure_zero()` with documented explanation
- Added typed `KemPublicKey` / `DsaPublicKey` — eliminated level-mismatch footgun
- Corrected README: honest scope statement, PQClean provenance, production warning
- Removed `key_info()` utility that could log partial key bytes
- Added output-size validation tests for all 6 parameter sets (30 tests total)

### v0.1.0
- Initial release: ML-KEM + ML-DSA, all 3 security levels, 16 tests

---

## License

MIT OR Apache-2.0

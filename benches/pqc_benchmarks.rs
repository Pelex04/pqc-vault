use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use pqc_vault::{SecurityLevel, kem::KemKeyPair, dsa::DsaKeyPair};

fn bench_kem_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("KEM Key Generation");
    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        g.bench_with_input(BenchmarkId::from_parameter(format!("{:?}", level)), &level, |b, &l| {
            b.iter(|| KemKeyPair::generate(black_box(l)).unwrap())
        });
    }
    g.finish();
}

fn bench_kem_encapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("KEM Encapsulate");
    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let kp = KemKeyPair::generate(level).unwrap();
        let pub_key = kp.public_key();
        g.bench_with_input(BenchmarkId::from_parameter(format!("{:?}", level)), &level, |b, _| {
            b.iter(|| KemKeyPair::encapsulate(black_box(&pub_key)).unwrap())
        });
    }
    g.finish();
}

fn bench_kem_decapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("KEM Decapsulate");
    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let kp  = KemKeyPair::generate(level).unwrap();
        let (ct, _) = KemKeyPair::encapsulate(&kp.public_key()).unwrap();
        g.bench_with_input(BenchmarkId::from_parameter(format!("{:?}", level)), &level, |b, _| {
            b.iter(|| kp.decapsulate(black_box(&ct)).unwrap())
        });
    }
    g.finish();
}

fn bench_dsa_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("DSA Key Generation");
    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        g.bench_with_input(BenchmarkId::from_parameter(format!("{:?}", level)), &level, |b, &l| {
            b.iter(|| DsaKeyPair::generate(black_box(l)).unwrap())
        });
    }
    g.finish();
}

fn bench_dsa_sign(c: &mut Criterion) {
    let mut g = c.benchmark_group("DSA Sign");
    let msg = b"benchmark message for post-quantum signature performance test";
    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let kp = DsaKeyPair::generate(level).unwrap();
        g.bench_with_input(BenchmarkId::from_parameter(format!("{:?}", level)), &level, |b, _| {
            b.iter(|| kp.sign(black_box(msg)).unwrap())
        });
    }
    g.finish();
}

fn bench_dsa_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("DSA Verify");
    let msg = b"benchmark message for post-quantum verification performance test";
    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let kp  = DsaKeyPair::generate(level).unwrap();
        let pub_key = kp.public_key();
        let sig = kp.sign(msg).unwrap();
        g.bench_with_input(BenchmarkId::from_parameter(format!("{:?}", level)), &level, |b, _| {
            b.iter(|| DsaKeyPair::verify_with_typed_key(black_box(&pub_key), black_box(msg), black_box(&sig)).unwrap())
        });
    }
    g.finish();
}

criterion_group!(benches,
    bench_kem_keygen, bench_kem_encapsulate, bench_kem_decapsulate,
    bench_dsa_keygen, bench_dsa_sign, bench_dsa_verify
);
criterion_main!(benches);

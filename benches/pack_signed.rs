// Allows share test vectors between unit and integration tests
pub(crate) use didcomm;

#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};
use didcomm::{did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver};

use test_vectors::{
    ALICE_AUTH_METHOD_25519, ALICE_AUTH_METHOD_P256, ALICE_AUTH_METHOD_SECPP256K1, ALICE_DID_DOC,
    ALICE_SECRETS, MESSAGE_SIMPLE,
};

// Here we have an async function to benchmark
async fn pack_signed(
    sign_by: &str,
    did_resolver: &ExampleDIDResolver,
    secrets_resolver: &ExampleSecretsResolver,
) {
    MESSAGE_SIMPLE
        .pack_signed(sign_by, did_resolver, secrets_resolver)
        .await
        .expect("Unable pack_signed");
}

fn benchmarks(c: &mut Criterion) {
    let sign_by = &ALICE_AUTH_METHOD_25519.id;
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    c.bench_function("pack_signed_ed25519", move |b| {
        b.to_async(FuturesExecutor)
            .iter(|| pack_signed(sign_by, &did_resolver, &secrets_resolver));
    });

    let sign_by = &ALICE_AUTH_METHOD_P256.id;
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    c.bench_function("pack_signed_p256", move |b| {
        b.to_async(FuturesExecutor)
            .iter(|| pack_signed(sign_by, &did_resolver, &secrets_resolver));
    });

    let sign_by = &ALICE_AUTH_METHOD_SECPP256K1.id;
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    c.bench_function("pack_signed_k256", move |b| {
        b.to_async(FuturesExecutor)
            .iter(|| pack_signed(sign_by, &did_resolver, &secrets_resolver));
    });
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);

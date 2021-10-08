// Allows share test vectors between unit and integration tests
pub(crate) use didcomm;

#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};

use didcomm::{
    algorithms::AnonCryptAlg, did::resolvers::ExampleDIDResolver,
    secrets::resolvers::ExampleSecretsResolver, PackEncryptedOptions,
};

use test_vectors::{
    ALICE_AUTH_METHOD_25519, ALICE_AUTH_METHOD_P256, ALICE_AUTH_METHOD_SECPP256K1, ALICE_DID,
    ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
    MESSAGE_SIMPLE, BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
};

// Here we have an async function to benchmark
async fn pack_encrypted(
    to: &str,
    from: Option<&str>,
    sign_by: Option<&str>,
    did_resolver: &ExampleDIDResolver,
    secrets_resolver: &ExampleSecretsResolver,
    opts: &PackEncryptedOptions,
) {
    MESSAGE_SIMPLE
        .pack_encrypted(to, from, sign_by, did_resolver, secrets_resolver, opts)
        .await
        .expect("Unable pack_encrypted");
}

fn benchmarks(c: &mut Criterion) {
    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = None;

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_authcrypt_ed25519_1key", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = None;

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_1key_anoncrypt_a256cbc",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256gcmEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_1key_anoncrypt_a256gsm",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::Xc20pEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_1key_anoncrypt_xc20p",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = BOB_DID;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_authcrypt_ed25519_3keys", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = Some(ALICE_DID);
        let to = BOB_DID;
        let sign_by = None;

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_3keys_anoncrypt_a256cbc",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = BOB_DID;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256gcmEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_3keys_anoncrypt_a256gsm",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = BOB_DID;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::Xc20pEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_3keys_anoncrypt_xc20p",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = None;
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_anoncrypt_ed25519_a256cbc_1key", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = None;
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256gcmEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_anoncrypt_ed25519_a256gcm_1key", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = None;
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::Xc20pEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_anoncrypt_ed25519_xc20p_1key", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = None;
        let to = BOB_DID;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_anoncrypt_ed25519_a256cbc_3keys", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = None;
        let to = BOB_DID;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256gcmEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_anoncrypt_ed25519_a256gsm_3keys", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = None;
        let to = BOB_DID;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::Xc20pEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_anoncrypt_ed25519_xc20p_3keys", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id;
        let sign_by = None;

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_authcrypt_p256_1key", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id;
        let sign_by = None;

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_p256_1key_anoncrypt_a256cbc",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256gcmEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_p256_1key_anoncrypt_a256gsm",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id;
        let sign_by = None;
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::Xc20pEcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_p256_1key_anoncrypt_xc20p",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = Some(ALICE_AUTH_METHOD_25519.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_authcrypt_ed25519_1key_sign_x25519", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = Some(ALICE_AUTH_METHOD_P256.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_authcrypt_ed25519_1key_sign_p256", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = Some(ALICE_AUTH_METHOD_SECPP256K1.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            ..PackEncryptedOptions::default()
        };

        c.bench_function("pack_encrypted_authcrypt_ed25519_1key_sign_k256", move |b| {
            b.to_async(FuturesExecutor).iter(|| {
                pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
            });
        });
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = Some(ALICE_AUTH_METHOD_25519.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_1key_anoncrypt_a256cbc_sign_x25519",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = Some(ALICE_AUTH_METHOD_P256.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_1key_anoncrypt_a256cbc_sign_p256",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
        let sign_by = Some(ALICE_AUTH_METHOD_SECPP256K1.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_ed25519_1key_anoncrypt_a256cbc_sign_k256",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id;
        let sign_by = Some(ALICE_AUTH_METHOD_25519.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_p256_1key_anoncrypt_a256cbc_sign_e25519",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id;
        let sign_by = Some(ALICE_AUTH_METHOD_P256.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_p256_1key_anoncrypt_a256cbc_sign_p256",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }

    {
        let from = Some(ALICE_DID);
        let to = &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id;
        let sign_by = Some(ALICE_AUTH_METHOD_SECPP256K1.id.as_str());

        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let opts = PackEncryptedOptions {
            forward: false,
            protect_sender: true,
            enc_alg_anon: AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            ..PackEncryptedOptions::default()
        };

        c.bench_function(
            "pack_encrypted_authcrypt_p256_1key_anoncrypt_a256cbc_sign_k256",
            move |b| {
                b.to_async(FuturesExecutor).iter(|| {
                    pack_encrypted(to, from, sign_by, &did_resolver, &secrets_resolver, &opts)
                });
            },
        );
    }
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);

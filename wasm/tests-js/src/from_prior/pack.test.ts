import {
  ALICE_DID_DOC,
  CHARLIE_DID_DOC,
  CHARLIE_SECRETS,
  CHARLIE_SECRET_AUTH_KEY_ED25519,
  ExampleDIDResolver,
  ExampleSecretsResolver,
  FROM_PRIOR_FULL,
  FROM_PRIOR_MINIMAL,
} from "../test-vectors";

test.each([
  {
    from_prior: FROM_PRIOR_MINIMAL,
    issuer_kid: null,
    exp_kid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Minimal",
  },
  {
    from_prior: FROM_PRIOR_FULL,
    issuer_kid: null,
    exp_kid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Full",
  },
  {
    from_prior: FROM_PRIOR_FULL,
    issuer_kid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    exp_kid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Explicit key",
  },
])(
  "Message.pack-plaintext works for $case",
  async ({ from_prior, issuer_kid, exp_kid }) => {
    const did_resolver = new ExampleDIDResolver([ALICE_DID_DOC, CHARLIE_DID_DOC]);
    const secrets_resolver = new ExampleSecretsResolver(CHARLIE_SECRETS);

    const [packed, kid] = await from_prior.pack(
      issuer_kid,
      did_resolver,
      secrets_resolver
    );

    expect(typeof packed).toBe("string");
    expect(kid).toEqual(exp_kid);
  }
);

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
    fromPrior: FROM_PRIOR_MINIMAL,
    issuerKid: null,
    expKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Minimal",
  },
  {
    fromPrior: FROM_PRIOR_FULL,
    issuerKid: null,
    expKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Full",
  },
  {
    fromPrior: FROM_PRIOR_FULL,
    issuerKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    expKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Explicit key",
  },
])(
  "Message.pack-plaintext works for $case",
  async ({ fromPrior, issuerKid, expKid }) => {
    const didResolver = new ExampleDIDResolver([
      ALICE_DID_DOC,
      CHARLIE_DID_DOC,
    ]);
    const secretsResolver = new ExampleSecretsResolver(CHARLIE_SECRETS);

    const [packed, kid] = await fromPrior.pack(
      issuerKid,
      didResolver,
      secretsResolver
    );

    expect(typeof packed).toBe("string");
    expect(kid).toEqual(expKid);
  }
);

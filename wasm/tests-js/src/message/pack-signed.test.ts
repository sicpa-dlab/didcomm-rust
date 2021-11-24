import {
  MESSAGE_SIMPLE,
  ExampleDIDResolver,
  ALICE_DID_DOC,
  ExampleSecretsResolver,
  ALICE_SECRETS,
  ALICE_DID,
  MockDIDResolver,
  MockSecretsResolver,
} from "../test-vectors";

test.each([
  {
    case: "Signer DID not found",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    sign_by: "did:example:unknown",
    expError: "DID not resolved: Signer did not found",
  },
  {
    case: "Signer DID not a did",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    sign_by: "not-a-did",
    expError:
      "Illegal argument: `sign_from` value is not a valid DID or DID URL",
  },
  {
    case: "Signer DID URL not found",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    sign_by: `${ALICE_DID}#unknown`,
    expError: "DID not resolved: Signer key id not found in did doc",
  },
  {
    case: "DIDResolver error",
    didResolver: new MockDIDResolver(
      [
        () => {
          throw Error("Unknown error");
        },
      ],
      new ExampleDIDResolver([ALICE_DID_DOC])
    ),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    sign_by: ALICE_DID,
    expError:
      "Invalid state: Unable resolve signer did: Unable resolve did: Unknown error",
  },
  {
    case: "SecretsResolver::get_secrets error",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC]),
    secretsResolver: new MockSecretsResolver(
      [
        () => {
          throw Error("Unknown error");
        },
      ],
      [],
      new ExampleSecretsResolver(ALICE_SECRETS)
    ),
    message: MESSAGE_SIMPLE,
    sign_by: ALICE_DID,
    expError:
      "Invalid state: Unable get secret: Unable get secret: Unknown error",
  },
  {
    case: "SecretsResolver::find_secrets error",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC]),
    secretsResolver: new MockSecretsResolver(
      [],
      [
        () => {
          throw Error("Unknown error");
        },
      ],
      new ExampleSecretsResolver(ALICE_SECRETS)
    ),
    message: MESSAGE_SIMPLE,
    sign_by: ALICE_DID,
    expError:
      "Invalid state: Unable find secrets: Unable find secrets: Unknown error",
  },
])(
  "Message.pack-signed handles $case",
  async ({ didResolver, secretsResolver, message, sign_by, expError }) => {
    const res = message.pack_signed(sign_by, didResolver, secretsResolver);
    await expect(res).rejects.toThrowError(expError);
  }
);

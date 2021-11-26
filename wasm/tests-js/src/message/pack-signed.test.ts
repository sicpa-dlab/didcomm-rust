import {
  MESSAGE_SIMPLE,
  ExampleDIDResolver,
  ALICE_DID_DOC,
  PLAINTEXT_MSG_SIMPLE,
  MESSAGE_MINIMAL,
  MockDIDResolver,
  MockSecretsResolver,
  PLAINTEXT_MSG_MINIMAL,
  ExampleSecretsResolver,
  ALICE_SECRETS,
  ALICE_DID,
  ALICE_AUTH_METHOD_25519,
  ALICE_AUTH_METHOD_P256,
  ALICE_AUTH_METHOD_SECP256K1,
} from "../test-vectors";

import { FromPrior, Message, PackSignedMetadata } from "didcomm";

test.each([
  {
    message: MESSAGE_SIMPLE,
    signBy: ALICE_DID,
    expMetadata: { sign_by_kid: ALICE_AUTH_METHOD_25519.id },
    case: "Simple message ED25519",
  },
  {
    message: MESSAGE_SIMPLE,
    signBy: ALICE_AUTH_METHOD_25519.id,
    expMetadata: { sign_by_kid: ALICE_AUTH_METHOD_25519.id },
    case: "Simple message ED25519",
  },
  {
    message: MESSAGE_SIMPLE,
    signBy: ALICE_AUTH_METHOD_P256.id,
    expMetadata: { sign_by_kid: ALICE_AUTH_METHOD_P256.id },
    case: "Simple message P256",
  },
  {
    message: MESSAGE_SIMPLE,
    signBy: ALICE_AUTH_METHOD_SECP256K1.id,
    expMetadata: { sign_by_kid: ALICE_AUTH_METHOD_SECP256K1.id },
    case: "Simple message K256",
  },
])(
  "Message.pack-signed works for $case",
  async ({ message, signBy, expMetadata }) => {
    const didResolver = new ExampleDIDResolver([ALICE_DID_DOC]);
    const secretResolver = new ExampleSecretsResolver(ALICE_SECRETS);

    const [signed, metadata] = await message.pack_signed(
      signBy,
      didResolver,
      secretResolver
    );

    expect(typeof signed).toStrictEqual("string");
    expect(metadata).toStrictEqual(expMetadata);

    const [unpacked, _] = await Message.unpack(
      signed,
      didResolver,
      secretResolver,
      {}
    );
    expect(unpacked.as_value()).toStrictEqual(message.as_value());
  }
);

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
    expError: "DID URL not found: Signer key id not found in did doc",
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

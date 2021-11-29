import {
  ALICE_AUTH_METHOD_25519,
  ALICE_AUTH_METHOD_P256,
  ALICE_AUTH_METHOD_SECP256K1,
  ALICE_DID,
  ALICE_DID_DOC,
  ALICE_SECRETS,
  ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
  ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
  ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET,
  BOB_DID,
  BOB_DID_DOC,
  BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
  BOB_SECRET_KEY_AGREEMENT_KEY_P384_1,
  BOB_SECRET_KEY_AGREEMENT_KEY_P521_1,
  BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
  BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
  BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
  BOB_SECRETS,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
  BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
  CHARLIE_DID,
  CHARLIE_DID_DOC,
  ExampleDIDResolver,
  ExampleSecretsResolver,
  MESSAGE_SIMPLE,
  MockDIDResolver,
  MockSecretsResolver,
} from "../test-vectors";
import { Message } from "didcomm";

test.each([
  {
    message: MESSAGE_SIMPLE,
    from: ALICE_DID,
    to: BOB_DID,
    expMetadata: {
      messaging_service: null,
      from_kid: ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
      sign_by_kid: null,
      to_kids: [
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
      ],
    },
    case: "Simple message X25519",
  },
  {
    message: MESSAGE_SIMPLE,
    from: ALICE_DID,
    to: BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
    expMetadata: {
      messaging_service: null,
      from_kid: ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
      sign_by_kid: null,
      to_kids: [BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
    },
    case: "Simple message P256",
  },
])(
  "Message.pack-encrypted authcrypt works for $case",
  async ({ message, from, to, expMetadata }) => {
    const didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
    let secretResolver = new ExampleSecretsResolver(ALICE_SECRETS);

    const [encrypted, metadata] = await message.pack_encrypted(
      to,
      from,
      null,
      didResolver,
      secretResolver,
      {
        protect_sender: false,
        forward: false,
        forward_headers: null,
        messaging_service: null,
        enc_alg_anon: "A256cbcHs512EcdhEsA256kw",
      }
    );

    expect(typeof encrypted).toStrictEqual("string");
    expect(metadata).toStrictEqual(expMetadata);

    secretResolver = new ExampleSecretsResolver(BOB_SECRETS);

    const [unpacked, _] = await Message.unpack(
      encrypted,
      didResolver,
      secretResolver,
      {}
    );

    expect(unpacked.as_value()).toStrictEqual(message.as_value());
  }
);

test.each([
  {
    case: "from is not a did or did url",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    from: "not-a-did",
    to: BOB_DID,
    signBy: ALICE_DID,
    expError: "Illegal argument: `from` value is not a valid DID or DID URL",
  },
  {
    case: "Signer DID not a did",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    from: ALICE_DID,
    to: "not-a-did",
    signBy: ALICE_DID,
    expError: "Illegal argument: `to` value is not a valid DID or DID URL",
  },
  {
    case: "Signer DID URL not found",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    from: ALICE_DID,
    to: BOB_DID,
    signBy: "not-a-did",
    expError:
      "Illegal argument: `sign_from` value is not a valid DID or DID URL",
  },
  {
    case: "from differs message from",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    from: BOB_DID,
    to: BOB_DID,
    signBy: ALICE_DID,
    expError:
      "Illegal argument: `message.from` value is not equal to `from` value's DID",
  },
  {
    case: "to differs message to",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, CHARLIE_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    from: ALICE_DID,
    to: CHARLIE_DID,
    signBy: ALICE_DID,
    expError:
      "Illegal argument: `message.to` value does not contain `to` value's DID",
  },
  {
    case: "from unknown did",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: new Message({
      id: "1234567890",
      typ: "application/didcomm-plain+json",
      type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
      from: "did:example:unknown",
      to: ["did:example:bob"],
      created_time: 1516269022,
      expires_time: 1516385931,
      body: { messagespecificattribute: "and its value" },
    }),
    from: "did:example:unknown",
    to: BOB_DID,
    signBy: ALICE_DID,
    expError: "DID not resolved: Sender did not found",
  },
  {
    case: "from unknown did url",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    from: ALICE_DID + "#unknown-key",
    to: BOB_DID,
    signBy: ALICE_DID,
    expError: "DID URL not found: No sender key agreements found",
  },
  {
    case: "from unknown did url",
    didResolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
    secretsResolver: new ExampleSecretsResolver(ALICE_SECRETS),
    message: MESSAGE_SIMPLE,
    from: "did:example:alice#key-x25519-not-in-secrets-1",
    to: BOB_DID,
    signBy: null,
    expError: "Secret not found: No sender secrets found",
  },
])(
  "Message.pack-encrypted handles $case",
  async ({
    didResolver,
    secretsResolver,
    message,
    from,
    to,
    signBy,
    expError,
  }) => {
    const res = message.pack_encrypted(
      to,
      from,
      signBy,
      didResolver,
      secretsResolver,
      {}
    );
    await expect(res).rejects.toThrowError(expError);
  }
);

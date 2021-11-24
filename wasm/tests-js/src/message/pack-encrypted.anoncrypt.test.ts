import {
  ALICE_AUTH_METHOD_25519,
  ALICE_AUTH_METHOD_P256,
  ALICE_AUTH_METHOD_SECP256K1,
  ALICE_DID,
  ALICE_DID_DOC,
  ALICE_SECRETS,
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
  ExampleDIDResolver,
  ExampleSecretsResolver,
  MESSAGE_SIMPLE,
} from "../test-vectors";
import { Message } from "didcomm-js";

test.each([
  {
    message: MESSAGE_SIMPLE,
    signBy: null,
    to: BOB_DID,
    expMetadata: {
      messaging_service: null,
      from_kid: null,
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
    signBy: null,
    to: BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
    expMetadata: {
      messaging_service: null,
      from_kid: null,
      sign_by_kid: null,
      to_kids: [BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
    },
    case: "Simple message P256",
  },
  {
    message: MESSAGE_SIMPLE,
    signBy: ALICE_AUTH_METHOD_25519.id,
    to: BOB_DID,
    expMetadata: {
      messaging_service: null,
      from_kid: null,
      sign_by_kid: ALICE_AUTH_METHOD_25519.id,
      to_kids: [BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id],
    },
    case: "Simple message X25519 signed",
  },
  {
    message: MESSAGE_SIMPLE,
    signBy: ALICE_AUTH_METHOD_P256.id,
    to: BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
    expMetadata: {
      messaging_service: null,
      from_kid: null,
      sign_by_kid: ALICE_AUTH_METHOD_P256.id,
      to_kids: [BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
    },
    case: "Simple message P256 signed",
  },
])(
  "Message.pack-encrypted anoncrypt works for $case",
  async ({ message, signBy, to, expMetadata }) => {
    const didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
    let secretResolver = new ExampleSecretsResolver(ALICE_SECRETS);

    const [encrypted, metadata] = await message.pack_encrypted(
      to,
      null,
      signBy,
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

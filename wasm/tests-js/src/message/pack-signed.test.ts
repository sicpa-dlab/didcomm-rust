import {
  MESSAGE_SIMPLE,
  ExampleDIDResolver,
  ALICE_DID_DOC,
  PLAINTEXT_MSG_SIMPLE,
  MESSAGE_MINIMAL,
  PLAINTEXT_MSG_MINIMAL,
  ExampleSecretsResolver,
  ALICE_SECRETS,
  ALICE_DID,
  ALICE_AUTH_METHOD_25519,
  ALICE_AUTH_METHOD_P256,
  ALICE_AUTH_METHOD_SECP256K1,
} from "../test-vectors";

import { FromPrior, Message, PackSignedMetadata } from "didcomm-js";

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

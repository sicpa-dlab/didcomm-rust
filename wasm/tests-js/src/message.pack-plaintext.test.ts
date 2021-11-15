import {
  MESSAGE_SIMPLE,
  ExampleDIDResolver,
  ALICE_DID_DOC,
  PLAINTEXT_MSG_SIMPLE,
  MESSAGE_MINIMAL,
  PLAINTEXT_MSG_MINIMAL,
} from "./test-vectors";

test.each([
  {
    message: MESSAGE_SIMPLE,
    plaintext_exp: PLAINTEXT_MSG_SIMPLE,
    case: "Simple message",
  },
  {
    message: MESSAGE_MINIMAL,
    plaintext_exp: PLAINTEXT_MSG_MINIMAL,
    case: "Minimal message",
  },
])(
  "Message.pack-plaintext works for $case",
  async ({ message, plaintext_exp }) => {
    let did_resolver = new ExampleDIDResolver([ALICE_DID_DOC]);
    let plaintext = await message.pack_plaintext(did_resolver);

    plaintext = JSON.parse(plaintext);
    plaintext_exp = JSON.parse(plaintext_exp);
    expect(plaintext).toStrictEqual(plaintext_exp);
  }
);

import {
  MESSAGE_SIMPLE,
  ExampleDIDResolver,
  ALICE_DID_DOC,
  PLAINTEXT_MSG_SIMPLE,
  MESSAGE_MINIMAL,
  PLAINTEXT_MSG_MINIMAL,
  MESSAGE_FROM_PRIOR,
  PLAINTEXT_FROM_PRIOR,
  BOB_DID_DOC,
  CHARLIE_DID_DOC,
} from "../test-vectors";

test.each([
  {
    message: MESSAGE_SIMPLE,
    plaintext_exp: PLAINTEXT_MSG_SIMPLE,
    case: "Simple",
  },
  {
    message: MESSAGE_MINIMAL,
    plaintext_exp: PLAINTEXT_MSG_MINIMAL,
    case: "Minimal",
  },
  {
    message: MESSAGE_FROM_PRIOR,
    plaintext_exp: PLAINTEXT_FROM_PRIOR,
    case: "FromPrior",
  },
])(
  "Message.pack-plaintext works for $case",
  async ({ message, plaintext_exp }) => {
    const did_resolver = new ExampleDIDResolver([
      ALICE_DID_DOC,
      BOB_DID_DOC,
      CHARLIE_DID_DOC,
    ]);

    const plaintext = await message.pack_plaintext(did_resolver);

    expect(JSON.parse(plaintext)).toStrictEqual(JSON.parse(plaintext_exp));
  }
);

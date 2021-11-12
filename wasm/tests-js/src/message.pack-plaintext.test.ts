import {
  MESSAGE_SIMPLE,
  ExampleDIDResolver,
  ALICE_DID_DOC,
  PLAINTEXT_MSG_SIMPLE,
  MESSAGE_MINIMAL,
  PLAINTEXT_MSG_MINIMAL,
} from "./test-vectors";

test.each([
  [MESSAGE_SIMPLE, PLAINTEXT_MSG_SIMPLE],
  [MESSAGE_MINIMAL, PLAINTEXT_MSG_MINIMAL],
])("Message.pack-plaintext works", async (message, plaintext_exp) => {
  let did_resolver = new ExampleDIDResolver([ALICE_DID_DOC]);
  let plaintext = await message.pack_plaintext(did_resolver);

  plaintext = JSON.parse(plaintext);
  plaintext_exp = JSON.parse(plaintext_exp);
  expect(plaintext).toStrictEqual(plaintext_exp);
});

import { Message } from "didcomm";
import {
  ALICE_DID,
  ALICE_DID_DOC,
  ALICE_SECRETS,
  BOB_DID,
  BOB_DID_DOC,
  BOB_SECRETS,
} from "./test-vectors";
import {
  ExampleDIDResolver,
  ExampleSecretsResolver,
} from "../../tests-js/src/test-vectors";

async function main() {
  // --- Building message from ALICE to BOB ---
  const msg = new Message({
    id: "1234567890",
    typ: "application/didcomm-plain+json",
    type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    from: "did:example:alice",
    to: ["did:example:bob"],
    created_time: 1516269022,
    expires_time: 1516385931,
    attachments: [
      {
        data: {
          json: { foo: "bar" },
        },
        id: "123",
        description: "example",
        media_type: "application/didcomm-encrypted+json",
      },
    ],
    body: { messagespecificattribute: "and its value" },
  });

  // --- Packing encrypted and authenticated message ---
  let didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
  let secretsResolver = new ExampleSecretsResolver(ALICE_SECRETS);

  const [encryptedMsg, encryptMetadata] = await msg.pack_encrypted(
    BOB_DID,
    ALICE_DID,
    ALICE_DID,
    didResolver,
    secretsResolver,
    {
      forward: false, // TODO: should be true by default
    }
  );

  console.log("Encryption metadata is\n", encryptMetadata);

  // --- Sending message ---
  console.log("Sending message\n", encryptedMsg);

  // --- Unpacking message ---
  didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
  secretsResolver = new ExampleSecretsResolver(BOB_SECRETS);

  const [unpackedMsg, unpackMetadata] = await Message.unpack(
    encryptedMsg,
    didResolver,
    secretsResolver,
    {}
  );

  console.log("Reveived message is\n", unpackedMsg.as_value());
  console.log("Reveived message unpack metadata is\n", unpackMetadata);
}

main().catch((e) => console.log(e));

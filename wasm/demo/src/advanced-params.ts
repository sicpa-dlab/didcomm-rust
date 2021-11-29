import { Message } from "didcomm-js";
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
    body: { messagespecificattribute: "and its value" },
  });

  // --- Packing encrypted and authenticated message ---
  let didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
  let secretsResolver = new ExampleSecretsResolver(ALICE_SECRETS);

  const [encryptedMsg, encryptMetadata] = await msg.pack_encrypted(
    "did:example:bob#key-p256-1",
    "did:example:alice#key-p256-1",
    "did:example:alice#key-2",
    didResolver,
    secretsResolver,
    {
      forward: false, // TODO: should be true by default
      protect_sender: true,
      enc_alg_anon: "A256cbcHs512EcdhEsA256kw",
      messaging_service: "did:example:bob#didcomm-1",
      enc_alg_auth: "A256cbcHs512Ecdh1puA256kw",
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

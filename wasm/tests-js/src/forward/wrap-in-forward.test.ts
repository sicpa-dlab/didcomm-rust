import { Message } from "didcomm";
import {
  IMESSAGE_SIMPLE,
  ExampleDIDResolver,
  ALICE_DID_DOC,
  BOB_DID_DOC,
  ALICE_DID,
} from "../test-vectors";

// TODO: more tests
test.each([
  {
    case: "Simple",
    message: IMESSAGE_SIMPLE,
    headers: { header1: "aaa", header2: "bbb" },
    to: ALICE_DID,
    routing_keys: ["did:example:bob#key-x25519-1"],
    enc_alg_anon: "A256cbcHs512EcdhEsA256kw",
    did_resolver: new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]),
  },
])(
  "Message.wrap-in-forward handles $case",
  async ({
    message,
    headers,
    to,
    routing_keys,
    enc_alg_anon,
    did_resolver,
  }) => {
    const res = await Message.wrap_in_forward(
      JSON.stringify(message),
      headers,
      to,
      routing_keys,
      enc_alg_anon,
      did_resolver
    );
    expect(typeof res).toStrictEqual("string");
    expect(res).toContain("ciphertext");
  }
);

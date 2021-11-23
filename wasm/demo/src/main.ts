import {
  ALICE_DID,
  ALICE_DID_DOC,
  ALICE_SECRETS,
  BOB_DID,
  BOB_DID_DOC,
  BOB_SECRETS,
} from "./test-vectors";

import {
  Message,
  DIDDoc,
  DIDResolver,
  Secret,
  SecretsResolver,
} from "didcomm-js";

class ExampleDIDResolver implements DIDResolver {
  knownDids: DIDDoc[];

  constructor(knownDids: DIDDoc[]) {
    this.knownDids = knownDids;
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    return this.knownDids.find((ddoc) => ddoc.did === did) || null;
  }
}

class ExampleSecretsResolver implements SecretsResolver {
  knownSecrets: Secret[];

  constructor(knownSecrets: Secret[]) {
    this.knownSecrets = knownSecrets;
  }

  async get_secret(secretId: string): Promise<Secret | null> {
    return this.knownSecrets.find((secret) => secret.id === secretId) || null;
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    return secretIds.filter((id) =>
      this.knownSecrets.find((secret) => secret.id === id)
    );
  }
}

async function main() {
  // --- Build message from ALICE to BOB ---

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
    BOB_DID,
    ALICE_DID,
    null,
    didResolver,
    secretsResolver,
    {
      forward: false,
    }
  );

  console.log("Encryption metadata is\n", encryptMetadata);

  // --- Send message ---

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

  console.log("Receved message is\n", unpackedMsg.as_value());
  console.log("Receved message unpack metadata is\n", unpackMetadata);
}

main().catch((e) => console.log(e));

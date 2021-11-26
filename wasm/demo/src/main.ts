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
import {CHARLIE_DID, CHARLIE_DID_DOC} from "../../tests-js/src/test-vectors";

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
    await nonRepudiableEncryption();
    await multiRecipient();
    await repudiableAuthentcatedEncryption();
    await repudiableNonAuthentcatedEncryption();
    await signedUnencrypteed();
}

async function nonRepudiableEncryption() {
    // --- Build message from ALICE to BOB ---

    const msg = new Message({
        id: "1234567890",
        typ: "application/didcomm-plain+json",
        type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        from: "did:example:alice",
        to: ["did:example:bob"],
        created_time: 1516269022,
        expires_time: 1516385931,
        body: {messagespecificattribute: "and its value"},
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

async function multiRecipient() {
    // --- Build message from ALICE to BOB and Charlie ---

    const msg = new Message({
        id: "1234567890",
        typ: "application/didcomm-plain+json",
        type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        from: "did:example:alice",
        to: ["did:example:bob", "did:example:charlie"],
        created_time: 1516269022,
        expires_time: 1516385931,
        body: {messagespecificattribute: "and its value"},
    });

    let didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC, CHARLIE_DID_DOC]);
    let secretsResolver = new ExampleSecretsResolver(ALICE_SECRETS);

    // --- Packing encrypted and authenticated message for Bob ---

    const [encryptedMsgBob, encryptMetadataBob] = await msg.pack_encrypted(
        BOB_DID,
        ALICE_DID,
        null,
        didResolver,
        secretsResolver,
        {
            forward: false,
        }
    );

    console.log("Encryption metadata for Bob is\n", encryptMetadataBob);

    // --- Send message ---

    console.log("Sending message to Bob\n", encryptedMsgBob);

    // --- Unpacking message ---

    // --- Packing encrypted and authenticated message for Bob ---

    const [encryptedMsgCharlie, encryptMetadataCharlie] = await msg.pack_encrypted(
        CHARLIE_DID,
        ALICE_DID,
        null,
        didResolver,
        secretsResolver,
        {
            forward: false,
        }
    );

    console.log("Encryption metadata for Charle is\n", encryptMetadataCharlie);

    // --- Send message ---

    console.log("Sending message to Charle\n", encryptedMsgCharlie);

    // --- Unpacking message for Bob ---

    didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
    secretsResolver = new ExampleSecretsResolver(BOB_SECRETS);

    const [unpackedMsgBob, unpackMetadataBob] = await Message.unpack(
        encryptedMsgBob,
        didResolver,
        secretsResolver,
        {}
    );

    console.log("Receved message for Bob is\n", unpackedMsgBob.as_value());
    console.log("Receved message unpack metadata for Bob is\n", unpackMetadataBob);

    // --- Unpacking message for Charlie ---

    didResolver = new ExampleDIDResolver([ALICE_DID_DOC, CHARLIE_DID_DOC]);
    secretsResolver = new ExampleSecretsResolver(BOB_SECRETS);

    const [unpackedMsgCharlie, unpackMetadataCharlie] = await Message.unpack(
        encryptedMsgBob,
        didResolver,
        secretsResolver,
        {}
    );

    console.log("Receved message for Charlie is\n", unpackedMsgCharlie.as_value());
    console.log("Receved message unpack metadata for Charlie is\n", unpackMetadataCharlie);
}

async function repudiableAuthentcatedEncryption() {
    // --- Build message from ALICE to BOB ---

    const msg = new Message({
        id: "1234567890",
        typ: "application/didcomm-plain+json",
        type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        from: "did:example:alice",
        to: ["did:example:bob"],
        created_time: 1516269022,
        expires_time: 1516385931,
        body: {messagespecificattribute: "and its value"},
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

async function repudiableNonAuthentcatedEncryption() {
    // --- Build message from ALICE to BOB ---

    const msg = new Message({
        id: "1234567890",
        typ: "application/didcomm-plain+json",
        type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        from: "did:example:alice",
        to: ["did:example:bob"],
        created_time: 1516269022,
        expires_time: 1516385931,
        body: {messagespecificattribute: "and its value"},
    });

    // --- Packing encrypted and authenticated message ---
    let didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
    let secretsResolver = new ExampleSecretsResolver(ALICE_SECRETS);

    const [encryptedMsg, encryptMetadata] = await msg.pack_encrypted(
        BOB_DID,
        null,
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

async function signedUnencrypteed() {
    // --- Build message from ALICE to BOB ---

    const msg = new Message({
        id: "1234567890",
        typ: "application/didcomm-plain+json",
        type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        from: "did:example:alice",
        to: ["did:example:bob"],
        created_time: 1516269022,
        expires_time: 1516385931,
        body: {messagespecificattribute: "and its value"},
    });

    // --- Packing encrypted and authenticated message ---
    let didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
    let secretsResolver = new ExampleSecretsResolver(ALICE_SECRETS);

    const [encryptedMsg, encryptMetadata] = await msg.pack_signed(
        ALICE_DID,
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

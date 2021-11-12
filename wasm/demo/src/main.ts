import { ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS } from "./test-vectors";
import { Message } from "didcomm-js";

type DIDDoc = any;

interface DIDResolver {
    resolve(did: String): Promise<DIDDoc | null>;
}

class ExampleDIDResolver implements DIDResolver {
    known_dids: Array<DIDDoc>;

    constructor(known_dids: Array<DIDDoc>) {
        this.known_dids = known_dids;
    }

    async resolve(did: String): Promise<DIDDoc | null> {
        return this.known_dids.find((ddoc) => ddoc.did == did);
    }
}

type Secret = any;

interface SecretsResolver {
    get_secret(secret_id: String): Promise<Secret | null>;

    find_secrets(secret_ids: Array<String>): Promise<Array<String>>;
}

class ExampleSecretsResolver implements SecretsResolver {
    known_secrets: Array<Secret>;

    constructor(known_secrets: Array<Secret>) {
        this.known_secrets = known_secrets;
    }

    async get_secret(secret_id: String): Promise<Secret | null> {
        return this.known_secrets.find((secret) => secret.id == secret_id);
    }

    async find_secrets(secret_ids: Array<String>): Promise<Array<String>> {
        let secrets = secret_ids.filter((id) => this.known_secrets.find((secret) => secret.id == id))
        return secrets;
    }
}

async function main() {

    // --- Build message from ALICE to BOB ---

    let msg = new Message({
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

    let did_resolver = new ExampleDIDResolver([ALICE_DID_DOC]);
    let secrets_resolver = new ExampleSecretsResolver(ALICE_SECRETS);

    let [encrypted_msg, encrypt_metadata] = await msg.pack_encrypted(
        BOB_DID, ALICE_DID, undefined, did_resolver, secrets_resolver, {
        forward: false,
    });

    console.log("Encryption metadata is\n", encrypt_metadata);

    // --- Send message ---

    console.log("Sending message\n", encrypted_msg);

    // --- Unpacking message ---

    did_resolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
    secrets_resolver = new ExampleSecretsResolver(BOB_SECRETS);

    let [unpacked_msg, unpack_metadata] = await Message.unpack(
        encrypted_msg, did_resolver, secrets_resolver, {}
    );

    console.log("Receved message is\n", unpacked_msg.as_value());
    console.log("Receved message unpack metadata is\n", unpack_metadata);
}

main().catch((e) => console.log(e))
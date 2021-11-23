import {
    MESSAGE_SIMPLE,
    ExampleDIDResolver,
    ALICE_DID_DOC,
    PLAINTEXT_MSG_SIMPLE,
    MESSAGE_MINIMAL,
    PLAINTEXT_MSG_MINIMAL, ExampleSecretsResolver, ALICE_SECRETS, ALICE_DID,
} from "./test-vectors";

import {PackSignedMetadata} from "didcomm-js";

test.each([
    {
        message: MESSAGE_SIMPLE,
        sign_by: ALICE_DID,
        sign_by_kid: "did:example:alice#key-3",
        payload: "132",
        case: "Simple message",
    },
    {
        message: MESSAGE_MINIMAL,
        sign_by: ALICE_DID,
        sign_by_kid: "did:example:alice#key-3",
        payload: "23",
        case: "Minimal message",
    },
])(
    "Message.pack-signed works for $case",
    async ({message, sign_by, sign_by_kid, payload}) => {
        let did_resolver = new ExampleDIDResolver([ALICE_DID_DOC]);
        let secret_resolver = new ExampleSecretsResolver(ALICE_SECRETS);
        let result  = await message.pack_signed(sign_by, did_resolver, secret_resolver);
        let msg = result[0];
        let actual_metadata = result[1];

        let expected_metadata : PackSignedMetadata = {sign_by_kid: sign_by_kid}
        expect(actual_metadata == expected_metadata)

        let parsed_msg = JSON.parse(msg);

        expect(parsed_msg['payload'] == JSON.parse(payload));
        expect(typeof parsed_msg["signature"] === 'string')
        expect(parsed_msg["signature"] === sign_by)
    }
);

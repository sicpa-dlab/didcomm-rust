import { MESSAGE_SIMPLE, ExampleDIDResolver, ALICE_DID_DOC, PLAINTEXT_MSG_SIMPLE } from "./test-vectors";

test('Message.pack-plaintext works', async () => {
    let did_resolver = new ExampleDIDResolver([ALICE_DID_DOC]);
    let plaintext = await MESSAGE_SIMPLE.pack_plaintext(did_resolver);

    plaintext = JSON.parse(plaintext);
    let plaintext_exp = JSON.parse(PLAINTEXT_MSG_SIMPLE);

    expect(plaintext).toStrictEqual(plaintext_exp);
})
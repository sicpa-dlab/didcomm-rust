import { Message } from "didcomm-js";

test('Message.new works', () => {
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

    expect(msg).toBeInstanceOf(Message);
});

test('Message.as_value works', () => {
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

    let val = msg.as_value();

    expect(val).toStrictEqual({
        id: "1234567890",
        typ: "application/didcomm-plain+json",
        type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        from: "did:example:alice",
        to: ["did:example:bob"],
        created_time: 1516269022,
        expires_time: 1516385931,
        body: { messagespecificattribute: "and its value" },
    })
});
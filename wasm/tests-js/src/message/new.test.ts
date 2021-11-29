import { Message, IMessage } from "didcomm";

test("Message.new works", () => {
  const val: IMessage = {
    id: "example-1",
    typ: "application/didcomm-plain+json",
    type: "example/v1",
    body: "example-body",
    from: "did:example:4",
    to: ["did:example:1", "did:example:2", "did:example:3"],
    thid: "example-thread-1",
    pthid: "example-parent-thread-1",
    "example-header-1": "example-header-1-value",
    "example-header-2": "example-header-2-value",
    created_time: 10000,
    expires_time: 20000,
    attachments: [
      {
        data: {
          base64: "ZXhhbXBsZQ==",
        },
        id: "attachment1",
      },
      {
        data: {
          json: "example",
        },
        id: "attachment2",
      },
      {
        data: {
          json: "example",
        },
        id: "attachment3",
      },
    ],
  };

  const msg = new Message(val);
  expect(msg.as_value()).toStrictEqual(val);
});

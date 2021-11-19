import {
  ALICE_DID,
  ALICE_DID_DOC,
  ALICE_SECRETS,
  BOB_DID,
  BOB_DID_DOC,
  ExampleDIDResolver,
  ExampleSecretsResolver,
  MESSAGE_SIMPLE,
  MockDIDResolver,
  MockSecretsResolver,
} from "./test-vectors";

test.each([
  {
    err: (() => {
      let e = Error("Some Malformed error");
      e.name = "DIDCommMalformed";
      return e;
    })(),
    exp_err:
      "Malformed: Unable resolve recipient did: Unable resolve did: Some Malformed error",
    case: "Malformed raised",
  },
  {
    err: (() => {
      let e = Error("Some IoError error");
      e.name = "DIDCommIoError";
      return e;
    })(),
    exp_err:
      "IO error: Unable resolve recipient did: Unable resolve did: Some IoError error",
    case: "IoError raised",
  },
  {
    err: (() => {
      let e = Error("Some InvalidState error");
      e.name = "DIDCommInvalidState";
      return e;
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: Some InvalidState error",
    case: "InvalidState raised",
  },
  {
    err: (() => {
      return Error("Unknown error");
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: Unknown error",
    case: "Error raised",
  },
  {
    err: (() => {
      return "String error";
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: String error",
    case: "String raised",
  },
  {
    err: (() => {
      return 123;
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: JsValue(123)",
    case: "Unusual raised",
  },
])(
  "DIDReslver.resolve exception is propogated for $case",
  async ({ err, exp_err }) => {
    const did_resolver = new MockDIDResolver(
      [
        () => {
          throw err;
        },
      ],
      new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC])
    );

    const secrets_resolver = new ExampleSecretsResolver(ALICE_SECRETS);

    const res = MESSAGE_SIMPLE.pack_encrypted(
      BOB_DID,
      ALICE_DID,
      null,
      did_resolver,
      secrets_resolver,
      {
        forward: false,
      }
    );

    await expect(res).rejects.toThrowError(exp_err);
  }
);

test.each([
  {
    err: (() => {
      let e = Error("Some Malformed error");
      e.name = "DIDCommMalformed";
      return e;
    })(),
    exp_err:
      "Malformed: Unable resolve sender secret: Unable get secret: Some Malformed error",
    case: "Malformed raised",
  },
  {
    err: (() => {
      let e = Error("Some IoError error");
      e.name = "DIDCommIoError";
      return e;
    })(),
    exp_err:
      "IO error: Unable resolve sender secret: Unable get secret: Some IoError error",
    case: "IoError raised",
  },
  {
    err: (() => {
      let e = Error("Some InvalidState error");
      e.name = "DIDCommInvalidState";
      return e;
    })(),
    exp_err:
      "Invalid state: Unable resolve sender secret: Unable get secret: Some InvalidState error",
    case: "InvalidState raised",
  },
  {
    err: (() => {
      return Error("Unknown error");
    })(),
    exp_err:
      "Invalid state: Unable resolve sender secret: Unable get secret: Unknown error",
    case: "Error raised",
  },
  {
    err: (() => {
      return "String error";
    })(),
    exp_err:
      "Invalid state: Unable resolve sender secret: Unable get secret: String error",
    case: "String raised",
  },
  {
    err: (() => {
      return 123;
    })(),
    exp_err:
      "Invalid state: Unable resolve sender secret: Unable get secret: JsValue(123)",
    case: "Unusual raised",
  },
])(
  "Secrets.get_secret exception is propogated for $case",
  async ({ err, exp_err }) => {
    const did_resolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);

    const secrets_resolver = new MockSecretsResolver(
      [
        () => {
          throw err;
        },
      ],
      [],
      new ExampleSecretsResolver(ALICE_SECRETS)
    );

    const res = MESSAGE_SIMPLE.pack_encrypted(
      BOB_DID,
      ALICE_DID,
      null,
      did_resolver,
      secrets_resolver,
      {
        forward: false,
      }
    );

    await expect(res).rejects.toThrowError(exp_err);
  }
);

test.each([
  {
    err: (() => {
      let e = Error("Some Malformed error");
      e.name = "DIDCommMalformed";
      return e;
    })(),
    exp_err:
      "Malformed: Unable find secrets: Unable find secrets: Some Malformed error",
    case: "Malformed raised",
  },
  {
    err: (() => {
      let e = Error("Some IoError error");
      e.name = "DIDCommIoError";
      return e;
    })(),
    exp_err:
      "IO error: Unable find secrets: Unable find secrets: Some IoError error",
    case: "IoError raised",
  },
  {
    err: (() => {
      let e = Error("Some InvalidState error");
      e.name = "DIDCommInvalidState";
      return e;
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: Some InvalidState error",
    case: "InvalidState raised",
  },
  {
    err: (() => {
      return Error("Unknown error");
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: Unknown error",
    case: "Error raised",
  },
  {
    err: (() => {
      return "String error";
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: String error",
    case: "String raised",
  },
  {
    err: (() => {
      return 123;
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: JsValue(123)",
    case: "Unusual raised",
  },
])(
  "Secrets.find_secrets exception is propogated for $case",
  async ({ err, exp_err }) => {
    const did_resolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);

    const secrets_resolver = new MockSecretsResolver(
      [],
      [
        () => {
          throw err;
        },
      ],
      new ExampleSecretsResolver(ALICE_SECRETS)
    );

    const res = MESSAGE_SIMPLE.pack_encrypted(
      BOB_DID,
      ALICE_DID,
      null,
      did_resolver,
      secrets_resolver,
      {
        forward: false,
      }
    );

    await expect(res).rejects.toThrowError(exp_err);
  }
);

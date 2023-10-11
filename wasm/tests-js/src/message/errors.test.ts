import {
  ALICE_DID,
  ALICE_DID_DOC,
  ALICE_SECRETS,
  BOB_DID,
  BOB_DID_DOC,
  ExampleDIDResolver,
  ExampleKMS,
  MESSAGE_SIMPLE,
  MockDIDResolver,
  MockKMS,
} from "../test-vectors";

test.each([
  {
    err: (() => {
      const e = Error("Some Malformed error");
      e.name = "DIDCommMalformed";
      return e;
    })(),
    exp_err:
      "Malformed: Unable resolve recipient did: Unable resolve did: Some Malformed error",
    case: "Malformed",
  },
  {
    err: (() => {
      const e = Error("Some IoError error");
      e.name = "DIDCommIoError";
      return e;
    })(),
    exp_err:
      "IO error: Unable resolve recipient did: Unable resolve did: Some IoError error",
    case: "IoError",
  },
  {
    err: (() => {
      const e = Error("Some InvalidState error");
      e.name = "DIDCommInvalidState";
      return e;
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: Some InvalidState error",
    case: "InvalidState",
  },
  {
    err: (() => {
      return Error("Unknown error");
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: Unknown error",
    case: "Error",
  },
  {
    err: (() => {
      return "String error";
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: String error",
    case: "String",
  },
  {
    err: (() => {
      return 123;
    })(),
    exp_err:
      "Invalid state: Unable resolve recipient did: Unable resolve did: JsValue(123)",
    case: "Unusual",
  },
])(
  "DIDReslver.resolve exception is propogated for $case",
  async ({ err, exp_err }) => {
    const didResolver = new MockDIDResolver(
      [
        () => {
          throw err;
        },
      ],
      new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC])
    );

    const kms = new ExampleKMS(ALICE_SECRETS);

    const res = MESSAGE_SIMPLE.pack_encrypted(
      BOB_DID,
      ALICE_DID,
      null,
      didResolver,
      kms,
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
      const e = Error("Some Malformed error");
      e.name = "DIDCommMalformed";
      return e;
    })(),
    exp_err:
      "Malformed: Unable produce authcrypt envelope: Unable to derive kw: Unable to derive key: Some Malformed error",
    case: "Malformed",
  },
  {
    err: (() => {
      const e = Error("Some IoError error");
      e.name = "DIDCommIoError";
      return e;
    })(),
    exp_err:
      "IO error: Unable produce authcrypt envelope: Unable to derive kw: Unable to derive key: Some IoError error",
    case: "IoError",
  },
  {
    err: (() => {
      const e = Error("Some InvalidState error");
      e.name = "DIDCommInvalidState";
      return e;
    })(),
    exp_err:
      "Invalid state: Unable produce authcrypt envelope: Unable to derive kw: Unable to derive key: Some InvalidState error",
    case: "InvalidState",
  },
  {
    err: (() => {
      return Error("Unknown error");
    })(),
    exp_err:
      "Invalid state: Unable produce authcrypt envelope: Unable to derive kw: Unable to derive key: Unknown error",
    case: "Error",
  },
  {
    err: (() => {
      return "String error";
    })(),
    exp_err:
      "Invalid state: Unable produce authcrypt envelope: Unable to derive kw: Unable to derive key: String error",
    case: "String",
  },
  {
    err: (() => {
      return 123;
    })(),
    exp_err:
      "Invalid state: Unable produce authcrypt envelope: Unable to derive kw: Unable to derive key: JsValue(123)",
    case: "Unusual",
  },
])(
  "Secrets.derive exception is propogated for $case",
  async ({ err, exp_err }) => {
    const didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);

    const kms = new MockKMS(
      [
        () => {
          throw err;
        },
      ],
      [],
      [],
      [
        () => {
          throw err;
        },
      ],
      [
        () => {
          throw err;
        },
      ],
      new ExampleKMS(ALICE_SECRETS)
    );

    const res = MESSAGE_SIMPLE.pack_encrypted(
      BOB_DID,
      ALICE_DID,
      null,
      didResolver,
        kms,
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
      const e = Error("Some Malformed error");
      e.name = "DIDCommMalformed";
      return e;
    })(),
    exp_err:
      "Malformed: Unable find secrets: Unable find secrets: Some Malformed error",
    case: "Malformed",
  },
  {
    err: (() => {
      const e = Error("Some IoError error");
      e.name = "DIDCommIoError";
      return e;
    })(),
    exp_err:
      "IO error: Unable find secrets: Unable find secrets: Some IoError error",
    case: "IoError",
  },
  {
    err: (() => {
      const e = Error("Some InvalidState error");
      e.name = "DIDCommInvalidState";
      return e;
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: Some InvalidState error",
    case: "InvalidState",
  },
  {
    err: (() => {
      return Error("Unknown error");
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: Unknown error",
    case: "Error",
  },
  {
    err: (() => {
      return "String error";
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: String error",
    case: "String",
  },
  {
    err: (() => {
      return 123;
    })(),
    exp_err:
      "Invalid state: Unable find secrets: Unable find secrets: JsValue(123)",
    case: "Unusual",
  },
])(
  "Secrets.find_secrets exception is propogated for $case",
  async ({ err, exp_err }) => {
    const didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);

    const secretsResolver = new MockKMS(
      [],
      [
        () => {
          throw err;
        },
      ],
      [],
      [],
      [],
      new ExampleKMS(ALICE_SECRETS)
    );

    const res = MESSAGE_SIMPLE.pack_encrypted(
      BOB_DID,
      ALICE_DID,
      null,
      didResolver,
      secretsResolver,
      {
        forward: false,
      }
    );

    await expect(res).rejects.toThrowError(exp_err);
  }
);

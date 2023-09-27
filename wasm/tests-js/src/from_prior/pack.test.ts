import { FromPrior } from "didcomm";
import {
  ALICE_DID_DOC,
  CHARLIE_DID_DOC,
  CHARLIE_SECRETS,
  CHARLIE_SECRET_AUTH_KEY_ED25519,
  ExampleDIDResolver,
  ExampleKMS,
  FROM_PRIOR_FULL,
  FROM_PRIOR_MINIMAL,
} from "../test-vectors";

test.each([
  {
    fromPrior: FROM_PRIOR_MINIMAL,
    issuerKid: null,
    expKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Minimal",
  },
  {
    fromPrior: FROM_PRIOR_FULL,
    issuerKid: null,
    expKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Full",
  },
  {
    fromPrior: FROM_PRIOR_FULL,
    issuerKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    expKid: CHARLIE_SECRET_AUTH_KEY_ED25519.id,
    case: "Explicit key",
  },
])(
  "FromPrior.pack works for $case",
  async ({ fromPrior, issuerKid, expKid }) => {
    const didResolver = new ExampleDIDResolver([
      ALICE_DID_DOC,
      CHARLIE_DID_DOC,
    ]);

    const kms = new ExampleKMS(CHARLIE_SECRETS);

    const [packed, kid] = await fromPrior.pack(
      issuerKid,
      didResolver,
      kms
    );

    expect(typeof packed).toStrictEqual("string");
    expect(kid).toStrictEqual(expKid);

    const [unpacked, _] = await FromPrior.unpack(packed, didResolver);
    expect(unpacked.as_value()).toStrictEqual(fromPrior.as_value());
  }
);

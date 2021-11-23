import { FromPrior } from "didcomm-js";
import {
  ALICE_DID_DOC,
  CHARLIE_DID_DOC,
  CHARLIE_SECRET_AUTH_KEY_ED25519,
  ExampleDIDResolver,
  FROM_PRIOR_JWT_FULL,
  FROM_PRIOR_JWT_INVALID,
  FROM_PRIOR_JWT_INVALID_SIGNATURE,
  IFROM_PRIOR_FULL,
} from "../test-vectors";

test("FromPrior.unpack works", async () => {
  const didResolver = new ExampleDIDResolver([ALICE_DID_DOC, CHARLIE_DID_DOC]);

  const [fromPrior, issuerKid] = await FromPrior.unpack(
    FROM_PRIOR_JWT_FULL,
    didResolver
  );

  // TODO: Use toStrictEq check after reduction of FromPrior fields
  expect(fromPrior.as_value()).toMatchObject(IFROM_PRIOR_FULL);

  expect(issuerKid).toStrictEqual(CHARLIE_SECRET_AUTH_KEY_ED25519.id);
});

test.each([
  {
    jwt: FROM_PRIOR_JWT_INVALID,
    exp_err: "Malformed: Unable to parse compactly serialized JWS",
    case: "Malformed",
  },
  {
    jwt: FROM_PRIOR_JWT_INVALID_SIGNATURE,
    exp_err:
      "Malformed: Unable to verify from_prior signature: Unable decode signature: Invalid last symbol 66, offset 85.",
    case: "Invalid signature",
  },
])("FromPrior.unpack handles $case", async ({ jwt, exp_err }) => {
  const didResolver = new ExampleDIDResolver([ALICE_DID_DOC, CHARLIE_DID_DOC]);
  const res = FromPrior.unpack(jwt, didResolver);
  await expect(res).rejects.toThrowError(exp_err);
});

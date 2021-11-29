import { FromPrior, IFromPrior } from "didcomm";
import { ALICE_DID, BOB_DID, CHARLIE_DID } from ".";

export const IFROM_PRIOR_MINIMAL: IFromPrior = {
  iss: CHARLIE_DID,
  sub: ALICE_DID,
};

export const FROM_PRIOR_MINIMAL = new FromPrior(IFROM_PRIOR_MINIMAL);

export const IFROM_PRIOR_FULL = {
  iss: CHARLIE_DID,
  sub: ALICE_DID,
  iat: 123456,
};

export const FROM_PRIOR_FULL = new FromPrior(IFROM_PRIOR_FULL);

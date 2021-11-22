import { FromPrior } from "didcomm-js";
import { IFROM_PRIOR_FULL, IFROM_PRIOR_MINIMAL } from "../test-vectors";

test.each([
  { val: IFROM_PRIOR_MINIMAL, case: "Minimal" },
  { val: IFROM_PRIOR_FULL, case: "Full" },
])("FromPrior.new works for $case", ({ val }) => {
  const from_prior = new FromPrior(val);
  expect(from_prior.as_value()).toStrictEqual(val);
});

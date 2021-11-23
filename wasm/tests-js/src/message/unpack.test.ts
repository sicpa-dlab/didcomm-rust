import { Message } from "didcomm-js";
import {
  ALICE_DID_DOC,
  BOB_DID_DOC,
  BOB_SECRETS,
  CHARLIE_DID_DOC,
  ExampleDIDResolver,
  ExampleSecretsResolver,
  IMESSAGE_FROM_PRIOR,
  IMESSAGE_MINIMAL,
  IMESSAGE_SIMPLE,
  PLAINTEXT_FROM_PRIOR,
  PLAINTEXT_MSG_MINIMAL,
  PLAINTEXT_MSG_SIMPLE,
} from "../test-vectors";

test.each([
  {
    case: "Minimal",
    msg: PLAINTEXT_MSG_MINIMAL,
    options: {},
    expMsg: IMESSAGE_MINIMAL,
    expMetadata: {
      anonymous_sender: false,
      authenticated: false,
      enc_alg_anon: null,
      enc_alg_auth: null,
      encrypted: false,
      encrypted_from_kid: null,
      encrypted_to_kids: null,
      from_prior: null,
      from_prior_issuer_kid: null,
      non_repudiation: false,
      re_wrapped_in_forward: false,
      sign_alg: null,
      sign_from: null,
      signed_message: null,
    },
  },
  {
    case: "Simple",
    msg: PLAINTEXT_MSG_SIMPLE,
    options: {},
    expMsg: IMESSAGE_SIMPLE,
    expMetadata: {
      anonymous_sender: false,
      authenticated: false,
      enc_alg_anon: null,
      enc_alg_auth: null,
      encrypted: false,
      encrypted_from_kid: null,
      encrypted_to_kids: null,
      from_prior: null,
      from_prior_issuer_kid: null,
      non_repudiation: false,
      re_wrapped_in_forward: false,
      sign_alg: null,
      sign_from: null,
      signed_message: null,
    },
  },
  {
    case: "FromPrior",
    msg: PLAINTEXT_FROM_PRIOR,
    options: {},
    expMsg: IMESSAGE_FROM_PRIOR,
    expMetadata: {
      anonymous_sender: false,
      authenticated: false,
      enc_alg_anon: null,
      enc_alg_auth: null,
      encrypted: false,
      encrypted_from_kid: null,
      encrypted_to_kids: null,
      from_prior: {
        aud: "123",
        exp: 1234,
        iat: 123456,
        iss: "did:example:charlie",
        jti: "dfg",
        nbf: 12345,
        sub: "did:example:alice",
      },
      from_prior_issuer_kid: "did:example:charlie#key-1",
      non_repudiation: false,
      re_wrapped_in_forward: false,
      sign_alg: null,
      sign_from: null,
      signed_message: null,
    },
  },
])(
  "Message.unpack works for $case",
  async ({ msg, options, expMsg, expMetadata }) => {
    const didResolver = new ExampleDIDResolver([
      ALICE_DID_DOC,
      BOB_DID_DOC,
      CHARLIE_DID_DOC,
    ]);

    const secretsResolver = new ExampleSecretsResolver(BOB_SECRETS);

    const [unpacked, metadata] = await Message.unpack(
      msg,
      didResolver,
      secretsResolver,
      options
    );

    expect(unpacked.as_value()).toStrictEqual(expMsg);
    expect(metadata).toStrictEqual(expMetadata);
  }
);

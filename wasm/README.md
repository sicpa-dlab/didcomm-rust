# DIDComm JS

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Unit Tests](https://github.com/sicpa-dlab/didcomm-rust/workflows/verify/badge.svg)](https://github.com/sicpa-dlab/didcomm-rust/actions/workflows/verify.yml)

Basic [DIDComm v2](https://identity.foundation/didcomm-messaging/spec) support for modern browsers and NodeJS.

## Under the hood

This package is written in Rust using [didcomm](<(https://img.shields.io/crates/v/didcomm)>) crate. It compiles
to `wasm32` and exposes Javascript/Typescript API with [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen) help.
Also [wasmp-pack](https://github.com/rustwasm/wasm-pack) helps in packaging and publishing.

## Usage

To use `didcomm-js` install it with npm

```sh
npm install didcomm --save # If you plan use webpack or other bundler

npm install didcomm-node --save # If you plan use it without bandlers in NodeJS

```

**TODO: Exact package name will be defined after first release**

## Run demo

```sh
wasm-pack build --target nodejs # builds NodeJS package in pkg directiry
cd ./demo
npm install
npm run start
```

## Assumptions and Limitations

- This library requires `wasm32` compatible environment (modern browsers and recent NodeJS are supported).
- In order to use the library, `SecretsResolver` and `DIDResolver` interfaces must be implemented on the application level.
  Demo application provides 2 simple implementations `ExampleDIDResolver`
  and `ExampleSecretsResolver` that allows resolve locally known DID docs and secrets for tests/demo purposes.
- Verification materials are expected in JWK.
- Key IDs (kids) used in `SecretsResolver` must match the corresponding key IDs from DID Doc verification methods.
- Key IDs (kids) in DID Doc verification methods and secrets must be a full [DID Fragment](https://www.w3.org/TR/did-core/#fragment), that is `did#key-id`.
- Verification methods referencing another DID Document are not supported (see [Referring to Verification Methods](https://www.w3.org/TR/did-core/#referring-to-verification-methods)).
- The following curves and algorithms are supported:
  - Encryption:
    - Curves: X25519, P-256
    - Content encryption algorithms:
      - XC20P (to be used with ECDH-ES only, default for anoncrypt),
      - A256GCM (to be used with ECDH-ES only),
      - A256CBC-HS512 (default for authcrypt)
    - Key wrapping algorithms: ECDH-ES+A256KW, ECDH-1PU+A256KW
  - Signing:
    - Curves: Ed25519, Secp256k1, P-256
    - Algorithms: EdDSA (with crv=Ed25519), ES256, ES256K
- DIDComm has been implemented under the following [Assumptions](https://hackmd.io/i3gLqgHQR2ihVFV5euyhqg)

### **Features that will be supported in next versions**

- _Base58 and Multibase (internally Base58 only) formats for secrets and verification methods._
- _Forward protocol._

## Examples

A general usage of the API is the following:

- Sender Side:
  - Build a `Message` (plaintext, payload).
  - Convert a message to a DIDComm Message for further transporting by calling one of the following:
    - `Message.pack_encrypted` to build an Encrypted DIDComm message
    - `Message.pack_signed` to build a Signed DIDComm message
    - `Message.pack_plaintext` to build a Plaintext DIDComm message
- Receiver side:
  - Call `Message.unpack` on receiver side that will decrypt the message, verify signature if needed
    and return a `Message` for further processing on the application level.

### 1. Build an Encrypted DIDComm message for the given recipient

This is the most common DIDComm message to be used in most of the applications.

A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that

- hides its content from all but authorized recipients
- (optionally) discloses and proves the sender to only those recipients
- provides message integrity guarantees

It is important in privacy-preserving routing. It is what normally moves over network transports in DIDComm
applications, and is the safest format for storing DIDComm data at rest.

See `Message::pack_encrypted` documentation for more details.

**Authentication encryption** example (most common case):

```typescript
// --- Build message from ALICE to BOB ---
const msg = new Message({
  id: "1234567890",
  typ: "application/didcomm-plain+json",
  type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
  from: "did:example:alice",
  to: ["did:example:bob"],
  created_time: 1516269022,
  expires_time: 1516385931,
  body: { messagespecificattribute: "and its value" },
});

// --- Packing encrypted and authenticated message ---

let didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
let secretsResolver = new ExampleSecretsResolver(ALICE_SECRETS);

const [encryptedMsg, encryptMetadata] = await msg.pack_encrypted(
  BOB_DID,
  ALICE_DID,
  null,
  didResolver,
  secretsResolver,
  {
    forward: false, // Forward wrapping is unsupported in current version
  }
);

console.log("Encryption metadata is\n", encryptMetadata);

// --- Send message ---
console.log("Sending message\n", encryptedMsg);

// --- Unpacking message ---
didResolver = new ExampleDIDResolver([ALICE_DID_DOC, BOB_DID_DOC]);
secretsResolver = new ExampleSecretsResolver(BOB_SECRETS);

const [unpackedMsg, unpackMetadata] = await Message.unpack(
  encrypted_msg,
  didResolver,
  secretsResolver,
  {}
);

console.log("Receved message is\n", unpackedMsg.as_value());
console.log("Receved message unpack metadata is\n", unpackMetadata);
```

**Anonymous encryption** example:

```typescript
let [encryptedMsg, encryptMetadata] = await msg.pack_encrypted(
  BOB_DID,
  null, // Keep sender as None here
  null,
  didResolver,
  secretsResolver,
  {
    forward: false, // Forward wrapping is unsupported in current version
  }
);
```

**Encryption with non-repudiation** example:

```typescript
let [encrypted_msg, encrypt_metadata] = await msg.pack_encrypted(
  BOB_DID,
  ALICE_DID,
  ALICE_DID, // Provide information about signer here
  did_resolver,
  secrets_resolver,
  {
    forward: false, // Forward wrapping is unsupported in current version
  }
);
```

### 2. Build an unencrypted but Signed DIDComm message

Signed messages are only necessary when

- the origin of plaintext must be provable to third parties
- or the sender can’t be proven to the recipient by authenticated encryption because the recipient is not known in advance (e.g., in a
  broadcast scenario).

Adding a signature when one is not needed can degrade rather than enhance security because it
relinquishes the sender’s ability to speak off the record.

See `Message.pack_signed` documentation for more details.

```typescript
let [signed, metadata] = await msg.pack_signed(
  ALICE_DID,
  didResolver,
  secretsResolver
);
```

### 3. Build a Plaintext DIDComm message

A DIDComm message in its plaintext form that

- is not packaged into any protective envelope
- lacks confidentiality and integrity guarantees
- repudiable

They are therefore not normally transported across security boundaries.

```typescript
let plaintext = msg.pack_plaintext(didResolver).expect("Unable pack_plaintext");
```

## How to build with `wasm-pack build`

Install `wasm-pack` from https://rustwasm.github.io/wasm-pack/installer/ and then

```bash
wasm-pack build # Will output modules best-suited to be bundled with webpack
wasm-pack build --target=nodejs # Will output modules that can be directly consumed by NodeJS
wasm-pack build --target=web # Will output modules that can be directly consumed in browser without bundler usage
```

## How to test in NodeJS

```bash
wasm-pack build --target nodejs
cd ./tests-js
npm install
npm test
```

## How to test in Browser

```bash
wasm-pack build --target nodejs
cd ./tests-js
npm install
npm run test-puppeteer
```

_Note tests will be executed with jest+puppeteer in Chromium installed inside node_modules._

## Hot to publish to NPM with `wasm-pack publish`

```
wasm-pack publish
```

**TODO: Define package names and provide exact commands**

## 🔋 Batteries Included

- [`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen) for communicating
  between WebAssembly and JavaScript.
- [`console_error_panic_hook`](https://github.com/rustwasm/console_error_panic_hook)
  for logging panic messages to the developer console.
- [`wee_alloc`](https://github.com/rustwasm/wee_alloc), an allocator optimized
  for small code size.

## Contribution

PRs are welcome!

The following CI checks are run against every PR:

- No warnings from `cargo check --all-targets`
- No warnings from `npm run check` in `tests-js` directory
- No warnings from `npm run check` in `demo` directory
- All tests must pass with `npm test` in `tests-js` directory
- Rust code must be formatted by `cargo fmt --all`
- Javascript/Typescript code must be formatted by prettier `npx prettier --write .`

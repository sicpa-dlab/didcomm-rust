# DIDComm Rust + JavaScript/TypeScript + Swift

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Unit Tests](https://github.com/sicpa-dlab/didcomm-rust/workflows/verify/badge.svg)](https://github.com/sicpa-dlab/didcomm-rust/actions/workflows/verify.yml)
[![Rust Package](https://img.shields.io/crates/v/didcomm)](https://crates.io/crates/didcomm/)

The repository consists of the following main components:
- Basic [DIDComm v2](https://identity.foundation/didcomm-messaging/spec) support in Rust.
- [Wasm](https://webassembly.org/) - based DIDComm JavaScript/TypeScript, see [wasm](/wasm).
- [uniffi-rs](https://github.com/mozilla/uniffi-rs) - based wrappers
  - [uniffi](/uniffi) - callback-based Rust wrapper with uniffi-rs support
  - [wrappers/swift](/wrappers/swift) - Swift wrapper generated via uniffi-rs  

The docs below are provided for the main DIDComm Rust.

See [wasm/README.md](/wasm/README.md) for DIDComm JavaScript/TypeScript docs.

See [wrappers/swift/README.md](/wrappers/swift/README.md) for DIDComm Swift docs.

## Usage

To use `didcomm`, add this to your `Cargo.toml`:

```toml
[dependencies]
didcomm = "0.3"
```

## Run examples

Use `cargo run --example {example-name}` for example `cargo run --example basic`.

## Assumptions and Limitations
- Rust 2018 edition is required.
- In order to use the library, `SecretsResolver` and `DIDResolver` traits must be implemented on the application level. 
  Implementation of that traits is out of DIDComm library scope, but we provide 2 simple implementation `ExampleDIDResolver`
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

- *Base58 and Multibase (internally Base58 only) formats for secrets and verification methods.*
- *Forward protocol.*
- *DID rotation (`fromPrior` field).*


## Examples

See [examples](examples/) for details.

A general usage of the API is the following:
- Sender Side:
  - Build a `Message` (plaintext, payload).
  - Convert a message to a DIDComm Message for further transporting by calling one of the following:
     - `Message::pack_encrypted` to build an Encrypted DIDComm message
     - `Message::pack_signed` to build a Signed DIDComm message
     - `Message::pack_plaintext` to build a Plaintext DIDComm message
- Receiver side:
  - Call `Message::unpack` on receiver side that will decrypt the message, verify signature if needed
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

```rust
// --- Build message from ALICE to BOB ---
let msg = Message::build(
    "example-1".to_owned(),
    "example/v1".to_owned(),
    json!("example-body"),
)
.to(ALICE_DID.to_owned())
.from(BOB_DID.to_owned())
.finalize();

// --- Pack encrypted and authenticated message ---
let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

let (msg, metadata) = msg
    .pack_encrypted(
        BOB_DID,
        Some(ALICE_DID),
        None,
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted");

println!("Encryption metadata is\n{:?}\n", metadata);

// --- Send message ---
println!("Sending message \n{}\n", msg);

// --- Unpacking message ---
let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

let (msg, metadata) = Message::unpack(
    &msg,
    &did_resolver,
    &secrets_resolver,
    &UnpackOptions::default(),
)
.await
.expect("Unable unpack");

println!("Receved message is \n{:?}\n", msg);
println!("Receved message unpack metadata is \n{:?}\n", metadata);
```

**Anonymous encryption** example:

```rust
let (msg, metadata) = msg
    .pack_encrypted(
        BOB_DID,
        None, // Keep sender as None here
        None,
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted");
```

**Encryption with non-repudiation** example:

```rust
let (msg, metadata) = msg
    .pack_encrypted(
        BOB_DID,
        Some(ALICE_DID),
        Some(ALICE_DID), // Provide information about signer here
        &did_resolver,
        &secrets_resolver,
        &PackEncryptedOptions::default(),
    )
    .await
    .expect("Unable pack_encrypted");
```

### 2. Build an unencrypted but Signed DIDComm message

Signed messages are only necessary when
- the origin of plaintext must be provable to third parties
- or the sender can’t be proven to the recipient by authenticated encryption because the recipient is not known in advance (e.g., in a
broadcast scenario).
 
Adding a signature when one is not needed can degrade rather than enhance security because it
relinquishes the sender’s ability to speak off the record.

See `Message::pack_signed` documentation for more details.

```rust
// ALICE
let msg = Message::build(
    "example-1".to_owned(),
    "example/v1".to_owned(),
    json!("example-body"),
)
.to(ALICE_DID.to_owned())
.from(BOB_DID.to_owned())
.finalize();

let (msg, metadata) = msg
    .pack_signed(ALICE_DID, &did_resolver, &secrets_resolver)
    .await
    .expect("Unable pack_signed");

// BOB
let (msg, metadata) = Message::unpack(
    &msg,
    &did_resolver,
    &secrets_resolver,
    &UnpackOptions::default(),
)
.await
.expect("Unable unpack");
```

### 3. Build a Plaintext DIDComm message

A DIDComm message in its plaintext form that 
- is not packaged into any protective envelope
- lacks confidentiality and integrity guarantees
- repudiable

They are therefore not normally transported across security boundaries. 

```rust
// ALICE
let msg = Message::build(
    "example-1".to_owned(),
    "example/v1".to_owned(),
    json!("example-body"),
)
.to(ALICE_DID.to_owned())
.from(BOB_DID.to_owned())
.finalize();

let msg = msg
    .pack_plaintext(&did_resolver)
    .expect("Unable pack_plaintext");

// BOB
let (msg, metadata) = Message::unpack(
    &msg,
    &did_resolver,
    &secrets_resolver,
    &UnpackOptions::default(),
)
.await
.expect("Unable unpack");
```

## Contribution
PRs are welcome!

The following CI checks are run against every PR:
- No warnings from `cargo check --all-targets`
- All tests must pass with `cargo tests`
- Code must be formatted by `cargo fmt --all`

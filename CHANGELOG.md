# Changelog

All notable changes to this fork are documented here.

This is a fork of [sicpa-dlab/didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust),
diverged at `9e79b48`.

## 0.1.2

### Fixed

- `Message::unpack` rejects an encrypted message whose plaintext `to` does not
  contain the DID of the recipient `kid` (DIDComm Messaging v2.1, Message Layer
  Addressing Consistency). A `to` element may be a DID URL without a fragment,
  as the `to` header allows; its DID is what is compared.
- `Message::unpack` compares the DID of `from` with the authcrypt `skid` and the
  signer `kid`, so a `from` that is a DID URL without a fragment, as the `from`
  header allows, is no longer rejected. A `from` or `to` with a fragment is
  still rejected.
- `Message::pack_encrypted` accepts a plaintext whose `to` or `from` is a DID URL
  without a fragment, comparing its DID with the `to` and `from` arguments, so
  it can send what `Message::unpack` accepts.

## 0.1.1

### Fixed

- `Message::unpack` rejects a message whose plaintext `from` is not the DID of
  the authcrypt `skid` or of the signer `kid` (DIDComm Messaging v2.1, Message
  Layer Addressing Consistency).

## 0.1.0

### Changed

- `askar-crypto` comes from crates.io instead of a pinned `aries-askar` git
  revision, at `=0.3.3` (up from 0.2). The pin is exact: 0.3.6 added prehashed
  `SignatureType` variants that `KnownSignatureType` does not cover. `ES384`
  added for exhaustiveness.
- `uuid` gains the `stdweb` feature so v4 generation works on `wasm32`.
- Published as `equs-didcomm`; the library target stays `didcomm`, so
  `use didcomm::…` is unchanged.

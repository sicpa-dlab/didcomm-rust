## DIDComm FFI

### Build
As we need External Types wrapping for Swift, and it's not released yet, we have to rely on the master version:

`git clone git@github.com:mozilla/uniffi-rs.git`

`cargo install uniffi_bindgen --path uniffi-rs/uniffi_bindgen/`

`cargo build`

`uniffi-bindgen generate src/didcomm.udl --language kotlin -o uniffi-kotlin`

`uniffi-bindgen generate src/didcomm.udl --language swift -o uniffi-swift`
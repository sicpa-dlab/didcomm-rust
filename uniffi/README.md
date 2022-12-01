## DIDComm FFI
DIDComm bindings based on [uniffi-rs](https://github.com/mozilla/uniffi-rs).

It's used for [DIDComm Swift](../wrappers/swift) wrapper.

DIDComm uniffi has the following specific comparing to the core DIDComm crate:
- Callback-based versions of pack/unpack functions and DID/Secret resolver interfaces instead of async onces.
These pack/unpack functions wrap the corresponding async futures and execute them in a thread pool executor. 
The result is passed to a callback function.
- The language specific bidnings are generated for the API exposed in [didcomm.udl](src/didcomm.udl) file.

### Swift Build
1. Build:
```
cargo build --release
```

2. Install uniffi_bindgen:
```
cargo install uniffi_bindgen --version $(cargo pkgid uniffi | cut -f 2 -d '@')
```

3. Generate Swift binding:
```
uniffi-bindgen generate src/didcomm.udl --language swift -o ../wrappers/swift/didcomm
```

4. Compile a Swift module:
```
swiftc -module-name didcomm -emit-library -o ../wrappers/swift/didcomm/libdidcomm.dylib -emit-module -emit-module-path ../wrappers/swift/didcomm -parse-as-library -L ./target/debug/ -ldidcomm_uniffi -Xcc -fmodule-map-file=../wrappers/swift/didcomm/didcommFFI.modulemap ../wrappers/swift/didcomm/didcomm.swift
```
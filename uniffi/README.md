## DIDComm FFI

### Swift Build
As we need External Types wrapping for Swift, and it's not released yet, we have to rely on the master version:

1. Get local copy of uniffi-rs:
```
git clone git@github.com:mozilla/uniffi-rs.git
```

2. Install uniffi_bindgen:
```
cargo install uniffi_bindgen --path uniffi-rs/uniffi_bindgen/
```

3. Build:
```
cargo build
```

4. Generate Swift binding:
```
uniffi-bindgen generate src/didcomm.udl --language swift -o ../wrappers/swift/didcomm
```

5. Compile a Swift module:
```
swiftc -module-name didcomm -emit-library -o ../wrappers/swift/didcomm/libdidcomm.dylib -emit-module -emit-module-path ../wrappers/swift/didcomm -parse-as-library -L ./target/debug/ -ldidcomm_ffi -Xcc -fmodule-map-file=../wrappers/swift/didcomm/didcommFFI.modulemap ../wrappers/swift/didcomm/didcomm.swift
```
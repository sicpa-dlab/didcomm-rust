## Creating .a file for iOS.

Opens [Cargo.toml](./../../uniffi/Cargo.toml) file to change the `create-type`:
```
[lib]
crate-type = [
    'lib',
    'staticlib'
]
```

Go to UNIFFI folder [here](./../../uniffi/) and run:
```bash
cargo build --target aarch64-apple-ios
cargo build --target x86_64-apple-ios

lipo -create target/aarch64-apple-ios/debug/libdidcomm_uniffi.a target/x86_64-apple-ios/debug/libdidcomm_uniffi.a -output target/libDidcommiOS.a
```
We created a libDidcommiOS.a that runs both for iOS Simulator (arm64) and iOS Device (aarch64).

See the available architectures:
```
rustup target list
```

Verify the architecture:
```
lipo -info target/libDidcommiOS.a
```
Output: Architectures in the fat file: target/libDidcommiOS.a are: x86_64 arm64

### Also reed:

[Dealing with Rust to build PactSwiftMockServer](https://gist.github.com/surpher/bbf88e191e9d1f01ab2e2bbb85f9b528)
[Cross-compiling for Xcode](https://github.com/thombles/dw2019rust/blob/master/modules/02%20-%20Cross-compiling%20for%20Xcode.md)


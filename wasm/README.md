## WASM based javascript wrapper for DIDComm

### 🛠️ Build with `wasm-pack build`

```bash
wasm-pack build # Will output modules best-suited to be bundled with webpack
wasm-pack build --targed=nodejs # Will output modules that can be directly consumed by NodeJS
wasm-pack build --targed=web # Will output modules that can be directly consumed in browser without bundler usage
```

### 🔬 Test in NodeJS

```bash
wasm-pack build --target nodejs
cd ./tests-js
npm install
npm test
```

### 🔬 Test in Browser

```bash
wasm-pack build --target nodejs
cd ./tests-js
npm install
npm run test-puppeteer
```

*Note tests will be executed with jest+puppeteer in Chromium installed inside node_modules.*

### JS code formatting

```bash
npx prettier --write .
```

### 🎁 Publish to NPM with `wasm-pack publish`

```
wasm-pack publish
```

## 🔋 Batteries Included

* [`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen) for communicating
  between WebAssembly and JavaScript.
* [`console_error_panic_hook`](https://github.com/rustwasm/console_error_panic_hook)
  for logging panic messages to the developer console.
* [`wee_alloc`](https://github.com/rustwasm/wee_alloc), an allocator optimized
  for small code size.

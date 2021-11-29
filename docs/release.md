## Release

Assumptions:

*   `main` branch can wait until release PR is merged

The steps:

1.  **release**:
    1.  **review and adjust if needed the release version in `main`** to match the changes from the latest release following the [SemVer rules](https://semver.org/#summary).
    2.  [create](https://github.com/sicpa-dlab/didcomm-rust/compare/stable...main) a **PR from `main` to `stable`** (you may likely want to name it as `release-<version>`)
    3.  once merged [release pipeline](https://github.com/sicpa-dlab/didcomm-rust/actions/workflows/release.yml) will publish the release:
        *   to [crates.io](https://crates.io/crates/didcomm)
        *   to NPM:
            *   as Bundler(Webpack) compatible [package](https://www.npmjs.com/package/didcomm)
            *   as Node.js (CommonJS) compatible [package](https://www.npmjs.com/package/didcomm-node)
2.  **bump next release version in `main`**
    *   **Note** decision about the next release version should be based on the same [SemVer](https://semver.org/) rules and the expected changes. Usually it would be either a MINOR or MAJOR (if incompatible changes are planned) release.

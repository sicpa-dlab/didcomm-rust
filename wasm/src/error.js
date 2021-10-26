class DIDCommError extends Error {
    constructor(kind, ...args) {
        super(...args);
        this.name = this.constructor.name;
        this.kind = kind;
    }
}

exports.DIDCommError = DIDCommError
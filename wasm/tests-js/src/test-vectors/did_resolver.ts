import { DIDResolver, DIDDoc } from "didcomm-js";

export class ExampleDIDResolver implements DIDResolver {
  known_dids: DIDDoc[];

  constructor(known_dids: DIDDoc[]) {
    this.known_dids = known_dids;
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    return this.known_dids.find((ddoc) => ddoc.did == did);
  }
}

type MockResolve = (did: string) => DIDDoc | null;

export class MockDIDResolver implements DIDResolver {
  handlers: MockResolve[];
  fallback: DIDResolver;

  constructor(handlers: MockResolve[], fallback: DIDResolver) {
    this.handlers = handlers;
    this.fallback = fallback;
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    let handler = this.handlers.pop();
    return handler ? handler(did) : await this.fallback.resolve(did);
  }
}

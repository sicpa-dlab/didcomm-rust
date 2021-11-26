import { DIDResolver, DIDDoc } from "didcomm";

export class ExampleDIDResolver implements DIDResolver {
  knownDids: DIDDoc[];

  constructor(knownDids: DIDDoc[]) {
    this.knownDids = knownDids;
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    const res = this.knownDids.find((ddoc) => ddoc.did === did);
    return res ? res : null;
  }
}

type MockResolve = (did: string) => DIDDoc | null;

/* tslint:disable:max-classes-per-file */
export class MockDIDResolver implements DIDResolver {
  handlers: MockResolve[];
  fallback: DIDResolver;

  constructor(handlers: MockResolve[], fallback: DIDResolver) {
    this.handlers = handlers;
    this.fallback = fallback;
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    const handler = this.handlers.pop();
    return handler ? handler(did) : await this.fallback.resolve(did);
  }
}

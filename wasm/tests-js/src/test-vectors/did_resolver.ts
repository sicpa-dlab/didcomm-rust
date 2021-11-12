// TODO: typing mist be in d.ts file for didcomm-js

export type DIDDoc = any;

export interface DIDResolver {
  resolve(did: String): Promise<DIDDoc | null>;
}

export class ExampleDIDResolver implements DIDResolver {
  known_dids: Array<DIDDoc>;

  constructor(known_dids: Array<DIDDoc>) {
    this.known_dids = known_dids;
  }

  async resolve(did: String): Promise<DIDDoc | null> {
    return this.known_dids.find((ddoc) => ddoc.did == did);
  }
}

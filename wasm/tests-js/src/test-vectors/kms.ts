import {KeyManagementService, KnownKeyAlg} from "didcomm";
import {ariesAskar, Ecdh1PU, Jwk, Key, KeyAlgs, SigAlgs} from "@hyperledger/aries-askar-nodejs"
import { Secret} from "./secret";

type KnownSignatureType =
  /// Standard signature output for ed25519
  "EdDSA" |
  /// Elliptic curve DSA using P-256 and SHA-256
  "ES256" |
  /// Elliptic curve DSA using K-256 and SHA-256
  "ES256K" | string

/* tslint:disable:max-classes-per-file */
class KidOrJwk {
  Kid?: string
  X25519Key?: string
  P256Key?: string
}

export class ExampleKMS implements KeyManagementService {
  knownSecrets: Secret[];

  constructor(knownSecrets: Secret[]) {
    this.knownSecrets = knownSecrets;
  }

  _getKey(keyId: string): Key {
    const res = this.knownSecrets.find((secret) => secret.id === keyId);
    if (!res)
      throw new Error(`Unable to find key with id: ${keyId}`)
    return Key.fromJwk({jwk: Jwk.fromJson(res.privateKeyJwk)})
  }

  _resolveKey(x: KidOrJwk): Key {
    if (x.Kid) {
      return this._getKey(x.Kid)
    } else if (x.X25519Key) {
      return Key.fromJwk({jwk: Jwk.fromString(x.X25519Key) })
    } else if (x.P256Key) {
      return Key.fromJwk({jwk: Jwk.fromString(x.P256Key) })
    } else {
      throw new Error(`Invalid KidOrJwk: ${JSON.stringify(x)}`)
    }
  }

  async get_key_alg(secretId: string): Promise<KnownKeyAlg> {
    const key = this._getKey(secretId);
    switch (key.algorithm) {
      case "ed25519":
        return "Ed25519";
      case "x25519":
        return "X25519";
      case "p256":
        return "P256";
      case "k256":
        return "K256";
      default:
        return "Unsupported"
    }
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    return secretIds.filter((id) =>
      this.knownSecrets.find((secret) => secret.id === id)
    );
  }

  async create_signature(secretId: string, message: Uint8Array, sigType: KnownSignatureType | null): Promise<Uint8Array> {
    const key = this._getKey(secretId);
    let sigAlg = undefined
    switch (sigType) {
      case "EdDSA":
        sigAlg = SigAlgs.EdDSA;
        break;
      case "ES256":
        sigAlg = SigAlgs.ES256;
        break;
      case "ES256K":
        sigAlg = SigAlgs.ES256K;
        break;
      default:
        throw new Error("Unknown signature type")
    }
    return key.signMessage({message, sigType: sigAlg})
  }

  async derive_aes_key_using_ecdh_1pu(ephemKey: KidOrJwk, sendKey: KidOrJwk, recipKey: KidOrJwk, algId: Uint8Array, apu: Uint8Array, apv: Uint8Array, ccTag: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const ephemeralKey = this._resolveKey(ephemKey);
    const senderKey = this._resolveKey(sendKey);
    const recipientKey = this._resolveKey(recipKey);

    return new Key(ariesAskar.keyDeriveEcdh1pu({
      algorithm: KeyAlgs.AesA256Kw,
      ephemeralKey,
      recipientKey,
      senderKey,
      algId,
      apv,
      apu,
      ccTag,
      receive,
    })).secretBytes
  }

  async derive_aes_key_using_ecdh_es(ephemKey: KidOrJwk, recipKey: KidOrJwk, algId: Uint8Array, apu: Uint8Array, apv: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const ephemeralKey = this._resolveKey(ephemKey);
    const recipientKey = this._resolveKey(recipKey);

    const key = new Key(ariesAskar.keyDeriveEcdhEs({
      algorithm: KeyAlgs.AesA256Kw,
      ephemeralKey,
      recipientKey,
      algId,
      apv,
      apu,
      receive,
    }))

    return key.secretBytes
  }
}

type MockGetKeyAlg = (secretId: string) => KnownKeyAlg;
type MockFind = (secretIds: string[]) => string[];
type MockCreateSignature = (secretId: string, message: Uint8Array, sigType: KnownSignatureType | null) => Uint8Array;
type MockDeriveECDH1PU = (ephemKey: KidOrJwk, sendKey: KidOrJwk, recipKey: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, ccTag: Uint8Array, receive: boolean) => Uint8Array
type MockDeriveECDHES = (ephemKey: KidOrJwk, recipKey: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, receive: boolean) => Uint8Array

/* tslint:disable:max-classes-per-file */
export class MockKMS implements KeyManagementService {
  getKeyAlgHandlers: MockGetKeyAlg[];
  findHandlers: MockFind[];
  createSignatureHandlers: MockCreateSignature[];
  createDeriveECDH1PUHandlers: MockDeriveECDH1PU[];
  createDeriveECDHESHandlers: MockDeriveECDHES[];
  fallback: KeyManagementService;

  constructor(
    getKeyAlgHandlers: MockGetKeyAlg[],
    findHandlers: MockFind[],
    createSignatureHandlers: MockCreateSignature[],
    createDeriveECDH1PUHandlers: MockDeriveECDH1PU[],
    createDeriveECDHESHandlers: MockDeriveECDHES[],
    fallback: KeyManagementService
  ) {
    this.getKeyAlgHandlers = getKeyAlgHandlers;
    this.findHandlers = findHandlers;
    this.createSignatureHandlers = createSignatureHandlers;
    this.createDeriveECDH1PUHandlers = createDeriveECDH1PUHandlers;
    this.createDeriveECDHESHandlers = createDeriveECDHESHandlers;
    this.fallback = fallback;
  }

  async get_key_alg(secretId: string): Promise<KnownKeyAlg> {
    const handler = this.getKeyAlgHandlers.pop();

    return handler
        ? handler(secretId)
        : await this.fallback.get_key_alg(secretId);
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    const handler = this.findHandlers.pop();

    return handler
      ? handler(secretIds)
      : await this.fallback.find_secrets(secretIds);
  }

  async create_signature(secretId: string, message: Uint8Array, sigType: KnownSignatureType | null): Promise<Uint8Array> {
    const handler = this.createSignatureHandlers.pop();

    return handler
        ? handler(secretId, message, sigType)
        : await this.fallback.create_signature(secretId, message, sigType);
  }

  async derive_aes_key_using_ecdh_1pu(ephemKey: KidOrJwk, sendKey: KidOrJwk, recipKey: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, ccTag: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const handler = this.createDeriveECDH1PUHandlers.pop();

    return handler
        ? handler(ephemKey, sendKey, recipKey, alg, apu, apv, ccTag, receive)
        : await this.fallback.derive_aes_key_using_ecdh_1pu(ephemKey, sendKey, recipKey, alg, apu, apv, ccTag, receive);
  }

  async derive_aes_key_using_ecdh_es(ephemKey: KidOrJwk, recipKey: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const handler = this.createDeriveECDHESHandlers.pop();

    return handler
        ? handler(ephemKey, recipKey, alg, apu, apv, receive)
        : await this.fallback.derive_aes_key_using_ecdh_es(ephemKey, recipKey, alg, apu, apv, receive);
  }
}

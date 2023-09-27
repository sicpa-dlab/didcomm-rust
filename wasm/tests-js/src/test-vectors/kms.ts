import {KeyManagementService, KnownKeyAlg} from "didcomm";
import {ariesAskar, Ecdh1PU, Jwk, Key, KeyAlgs, SigAlgs} from "@hyperledger/aries-askar-nodejs"

type SecretType =
    "JsonWebKey2020" | "X25519KeyAgreementKey2019"
    | "Ed25519VerificationKey2018" | "EcdsaSecp256k1VerificationKey2019" | string

export class Secret {
  /**
   * A key ID identifying a secret (private key).
   */
  id: string;

  /**
   * Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
   */
  type: SecretType;

  /**
   * Possible value of the secret (private key)
   */
  privateKeyJwk: any;
  // privateKeyMultibase?: string;
  // privateKeyBase58?: string;

  // constructor(id: string, type: SecretType, privateKeyJwk: any) {
  //   this.id = id;
  //   this.type = type;
  //   this.privateKeyJwk = privateKeyJwk;
  // }
  //
  // public alg(): KnownKeyAlg {
  //   // "Ed25519" | "X25519" | "P256" | "K256"
  //   return "Ed25519"
  // }
  //
  // public key(): Key {
  //   return Key.fromJwk({jwk: this.privateKeyJwk })
  // }
}

type KnownSignatureType =
  /// Standard signature output for ed25519
  "EdDSA" |
  /// Elliptic curve DSA using P-256 and SHA-256
  "ES256" |
  /// Elliptic curve DSA using K-256 and SHA-256
  "ES256K" | string

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

  async get_key_alg(secret_id: string): Promise<KnownKeyAlg> {
    const key = this._getKey(secret_id);
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

  async create_signature(secret_id: string, message: Uint8Array, sig_type: KnownSignatureType | null): Promise<Uint8Array> {
    const key = this._getKey(secret_id);
    let sigAlg = undefined
    switch (sig_type) {
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
        throw "Unknown signature type"
    }
    return key.signMessage({message, sigType: sigAlg})
  }

  async derive_aes_key_using_ecdh_1pu(ephem_key: KidOrJwk, send_key: KidOrJwk, recip_key: KidOrJwk, algId: Uint8Array, apu: Uint8Array, apv: Uint8Array, ccTag: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const ephemeralKey = this._resolveKey(ephem_key);
    const recipientKey = this._resolveKey(recip_key);
    const senderKey = this._resolveKey(send_key);

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

  async derive_aes_key_using_ecdh_es(ephem_key: KidOrJwk, recip_key: KidOrJwk, algId: Uint8Array, apu: Uint8Array, apv: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const ephemeralKey = this._resolveKey(ephem_key);
    const recipientKey = this._resolveKey(recip_key);

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
type MockCreateSignature = (secret_id: string, message: Uint8Array, sig_type: KnownSignatureType | null) => Uint8Array;
type MockDeriveECDH1PU = (ephem_key: KidOrJwk, send_key: KidOrJwk, recip_key: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, cc_tag: Uint8Array, receive: boolean) => Uint8Array
type MockDeriveECDH1ES = (ephem_key: KidOrJwk, recip_key: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, receive: boolean) => Uint8Array

/* tslint:disable:max-classes-per-file */
export class MockKMS implements KeyManagementService {
  getKeyAlgHandlers: MockGetKeyAlg[];
  findHandlers: MockFind[];
  createSignatureHandlers: MockCreateSignature[];
  createDeriveECDH_1PUHandlers: MockDeriveECDH1PU[];
  createDeriveECDH_ESHandlers: MockDeriveECDH1ES[];
  fallback: KeyManagementService;

  constructor(
    getKeyAlgHandlers: MockGetKeyAlg[],
    findHandlers: MockFind[],
    createSignatureHandlers: MockCreateSignature[],
    createDeriveECDH_1PUHandlers: MockDeriveECDH1PU[],
    createDeriveECDH_ESHandlers: MockDeriveECDH1ES[],
    fallback: KeyManagementService
  ) {
    this.getKeyAlgHandlers = getKeyAlgHandlers;
    this.findHandlers = findHandlers;
    this.createSignatureHandlers = createSignatureHandlers;
    this.createDeriveECDH_1PUHandlers = createDeriveECDH_1PUHandlers;
    this.createDeriveECDH_ESHandlers = createDeriveECDH_ESHandlers;
    this.fallback = fallback;
  }

  async get_key_alg(secret_id: string): Promise<KnownKeyAlg> {
    const handler = this.getKeyAlgHandlers.pop();

    return handler
        ? handler(secret_id)
        : await this.fallback.get_key_alg(secret_id);
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    const handler = this.findHandlers.pop();

    return handler
      ? handler(secretIds)
      : await this.fallback.find_secrets(secretIds);
  }

  async create_signature(secret_id: string, message: Uint8Array, sig_type: KnownSignatureType | null): Promise<Uint8Array> {
    const handler = this.createSignatureHandlers.pop();

    return handler
        ? handler(secret_id, message, sig_type)
        : await this.fallback.create_signature(secret_id, message, sig_type);
  }

  async derive_aes_key_using_ecdh_1pu(ephem_key: KidOrJwk, send_key: KidOrJwk, recip_key: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, cc_tag: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const handler = this.createDeriveECDH_1PUHandlers.pop();

    return handler
        ? handler(ephem_key, send_key, recip_key, alg, apu, apv, cc_tag, receive)
        : await this.fallback.derive_aes_key_using_ecdh_1pu(ephem_key, send_key, recip_key, alg, apu, apv, cc_tag, receive);
  }

  async derive_aes_key_using_ecdh_es(ephem_key: KidOrJwk, recip_key: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, receive: boolean): Promise<Uint8Array> {
    const handler = this.createDeriveECDH_ESHandlers.pop();

    return handler
        ? handler(ephem_key, recip_key, alg, apu, apv, receive)
        : await this.fallback.derive_aes_key_using_ecdh_es(ephem_key, recip_key, alg, apu, apv, receive);
  }
}

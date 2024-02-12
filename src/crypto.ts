import nacl, { BoxKeyPair, SignKeyPair } from 'tweetnacl';
import { toByteArray, fromByteArray } from 'base64-js';
import { Range } from 'semver';

export type SymmetricKey = Uint8Array;
export type Nonce = Uint8Array;
export type PublicKey = { visibility: 'public', type: string, key: string };
export type PrivateKey = { visibility: 'private', type: string, key: string };

export interface EncryptionPublicKey extends PublicKey {
  type: 'encryption'
}
export interface EncryptionPrivateKey extends PrivateKey {
  type: 'encryption'
}

export interface SigningPublicKey extends PublicKey {
  type: 'signing'
}
export interface SigningPrivateKey extends PrivateKey {
  type: 'signing'
}

/**
 * DatagramMetadata - Type and version information.
 */
export interface DatagramMetadata {
  type: string;
  version: string;
}

// The Datagram is an internal representation of unencrypted data, and the consuming package
// shouldn't worry about its structure. Thus, it is private and not exported.
interface Datagram<T, M extends DatagramMetadata> {
  metadata: M;
  signature?: string;
  data: string;
}

/**
 * EncryptedDatagram - Typed encrypted AEAD object.
 * Easily serializable/deserializable as JSON for use over wire.
 */
export interface EncryptedDatagram<T, M extends DatagramMetadata> {
  payload: string; // base64 encoded encrypted bytes.
  metadata: M;
};

/**
 * DatagramCodec - Codec for serializing/deserializing datagrams for cryptography.
 */
export interface DatagramCodec<T, M extends DatagramMetadata>{
  metadata: M;
  versionRange: Range;
  serialize(data: T): Uint8Array;
  deserialize(bytes: Uint8Array): T;
}

/**
 * AEAD - Authenticated Encryption with Associated Data simplified!
 * 
 * This is the meat of the yaki-crypto library. This class hides all the complexity behind
 * encrypting and decrypting datagrams. Also, this class enforces Type Safety while encrypting
 * and decrypting datagram through the use of DatagramCodecs (Serialization/Deserialization helpers)
 * and DatagramMetadatas (part of the Associated Data).
 * 
 * Asymmetric Encryption requires signature verification through the use of public/private signing
 * keypairs, while Symmetric encryption can be optionally signed.
 * 
 * Underneath it all, this class uses the robust and well tested tweetnacl library.
 */
export class AEAD {
  private static sealDatagram<T, M extends DatagramMetadata>(datagram: Datagram<T,M>, publicKey: EncryptionPublicKey): Uint8Array{
    const encryptionKeypair = nacl.box.keyPair();
    const sealKey = nacl.box.before(toByteArray(publicKey.key), encryptionKeypair.secretKey);
    const encryptedMsg = this.encryptDatagram(datagram, sealKey);
    const fullMessage = new Uint8Array(encryptionKeypair.publicKey.length + encryptedMsg.length);
    fullMessage.set(encryptionKeypair.publicKey, 0);
    fullMessage.set(encryptedMsg, encryptionKeypair.publicKey.length);
    return fullMessage;
  }

  private static unsealDatagram<T, M extends DatagramMetadata>(bytes: Uint8Array, codec: DatagramCodec<T,M>, privateKey: EncryptionPrivateKey): Datagram<T, M> {
    const fullMessage = bytes;
    const encryptionPublicKey = fullMessage.slice(0, nacl.box.publicKeyLength);
    const encryptedMsg = fullMessage.slice(nacl.box.publicKeyLength);
    const sealKey = nacl.box.before(encryptionPublicKey, toByteArray(privateKey.key));
    return this.decryptDatagram(encryptedMsg, codec, sealKey);
  }

  private static encryptDatagram<T, M extends DatagramMetadata>(datagram: Datagram<T, M>, key: SymmetricKey): Uint8Array{
    const jsonString = JSON.stringify(datagram);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const box = nacl.secretbox(utf8StringToBytes(jsonString), nonce, key);
    const fullMessage = new Uint8Array(nonce.length + box.length);
    fullMessage.set(nonce, 0);
    fullMessage.set(box, nonce.length);
    return fullMessage
  }

  private static decryptDatagram<T, M extends DatagramMetadata>(bytes: Uint8Array, codec: DatagramCodec<T, M>, key: SymmetricKey): Datagram<T, M> {
    const fullMessage = bytes;
    const nonce = fullMessage.slice(0,nacl.secretbox.nonceLength);
    const msg = fullMessage.slice(nonce.length);
    const decryptedBytes = nacl.secretbox.open(msg, nonce, key);
    if (!decryptedBytes)
      throw Error('Could not decrypt the provided datagram using the key.');
    const jsonString = bytesToUtf8String(decryptedBytes);
    const decryptedDatagram = JSON.parse(jsonString);
    if (!(decryptedDatagram.metadata?.type && decryptedDatagram.metadata?.version && decryptedDatagram.data))
      throw Error('Invalid datagram decrypted with missing type, version and/or data.');
    if (decryptedDatagram.metadata?.type !== codec.metadata.type) {
      throw Error('Datagram type mismatch');
    }
    if (!codec.versionRange.test(decryptedDatagram.metadata.version)) {
      throw Error('Datagram version is incompatible with codec.');
    }
    return decryptedDatagram as Datagram<T,M>;
  }

  private static computeSignature(data: Uint8Array | string, signingKey: SigningPrivateKey): Uint8Array {
    const dataBytes = (typeof data === 'string') ? toByteArray(data) : data;
    const hash = nacl.hash(dataBytes);
    return nacl.sign.detached(hash, toByteArray(signingKey.key));
  }

  private static verifySignature(data: Uint8Array | string, signature: Uint8Array | string, verifyKey: SigningPublicKey): boolean {
    const dataBytes = (typeof data === 'string') ? toByteArray(data) : data;
    const signatureBytes = (typeof signature === 'string') ? toByteArray(signature) : signature;
    const hash = nacl.hash(dataBytes);
    return nacl.sign.detached.verify(hash, signatureBytes, toByteArray(verifyKey.key));
  }

  static encryptSymmetric<T, M extends DatagramMetadata>(data: T, codec: DatagramCodec<T,M>, key: SymmetricKey): EncryptedDatagram<T,M> {
    const datagram: Datagram<T,M>= {metadata: codec.metadata, data:fromByteArray(codec.serialize(data))};
    const bytes = fromByteArray(this.encryptDatagram(datagram, key));
    return { payload: bytes, metadata: codec.metadata };
  }

  static signAndEncryptSymmetric<T, M extends DatagramMetadata>(data: T, codec: DatagramCodec<T,M>, key: SymmetricKey, signingKey: SigningPrivateKey): EncryptedDatagram<T,M> {
    const serializedData = codec.serialize(data);
    const signature = this.computeSignature(serializedData, signingKey);
    const datagram: Datagram<T,M> = {metadata: codec.metadata, signature: fromByteArray(signature), data: fromByteArray(serializedData)};
    const bytes = fromByteArray(AEAD.encryptDatagram(datagram, key));
    return { payload: bytes, metadata: codec.metadata };
  }

  static encryptAsymmetric<T, M extends DatagramMetadata>(data: T, codec: DatagramCodec<T,M>, myPrivateKey: EncryptionPrivateKey, theirPublicKey: EncryptionPublicKey, mySigningPrivateKey: SigningPrivateKey): EncryptedDatagram<T,M> {
    const key = nacl.box.before(toByteArray(theirPublicKey.key), toByteArray(myPrivateKey.key));
    return AEAD.signAndEncryptSymmetric(data, codec, key, mySigningPrivateKey);    
  }

  static decryptSymmetric<T, M extends DatagramMetadata>(encrypted: EncryptedDatagram<T,M>, codec: DatagramCodec<T,M>, key: SymmetricKey): T {
    const datagram = AEAD.decryptDatagram(toByteArray(encrypted.payload), codec, key);
    return codec.deserialize(toByteArray(datagram.data));
  }

  static decryptSymmetricAndVerify<T, M extends DatagramMetadata>(encrypted: EncryptedDatagram<T,M>, codec: DatagramCodec<T,M>, key: SymmetricKey, signingPublicKey: SigningPublicKey): T {
    const datagram = AEAD.decryptDatagram(toByteArray(encrypted.payload), codec, key);
    if(!datagram.signature || !AEAD.verifySignature(datagram.data, datagram.signature, signingPublicKey))
      throw Error('Could not verify signature.');
    return codec.deserialize(toByteArray(datagram.data));
  }

  static decryptAsymmetric<T, M extends DatagramMetadata>(encrypted: EncryptedDatagram<T,M>, codec: DatagramCodec<T,M>, myPrivateKey: EncryptionPrivateKey, theirPublicKey: EncryptionPublicKey, theirSigningPublicKey: SigningPublicKey): T {
    const key = computeSharedKey(theirPublicKey, myPrivateKey);
    return AEAD.decryptSymmetricAndVerify(encrypted, codec, key, theirSigningPublicKey);
  }

  static seal<T, M extends DatagramMetadata>(data: T, codec: DatagramCodec<T,M>, theirPublicKey: EncryptionPublicKey): EncryptedDatagram<T,M> {
    const serializedData = codec.serialize(data);
    const datagram: Datagram<T,M> = {metadata: codec.metadata, data: fromByteArray(serializedData)};
    const bytes = fromByteArray(AEAD.sealDatagram(datagram, theirPublicKey));
    return { payload: bytes, metadata: codec.metadata };
  }

  static unseal<T, M extends DatagramMetadata>(encrypted: EncryptedDatagram<T,M>, codec: DatagramCodec<T,M>, myPrivateKey: EncryptionPrivateKey): T {
    const datagram = AEAD.unsealDatagram(toByteArray(encrypted.payload), codec, myPrivateKey);
    return codec.deserialize(toByteArray(datagram.data));
  }
}

export function computeSharedKey(theirPublicKey: EncryptionPublicKey, myPrivateKey: EncryptionPrivateKey): SymmetricKey {
  return nacl.box.before(toByteArray(theirPublicKey.key), toByteArray(myPrivateKey.key));
}

export const utf8StringToBytes = (data: string) => {
  const utf8encoder = new TextEncoder();
  return utf8encoder.encode(data);
};

export const bytesToUtf8String = (data: Uint8Array) => {
  const utf8decoder = new TextDecoder();
  return utf8decoder.decode(data);
};

export function trimAndLowercase(str: string) {
  return str.trim().toLowerCase();
}

/**
 * Typesafe KeyPair class for Public/Private Key Cryptography.
 */
export interface KeyPair {
  public: PublicKey;
  private: PrivateKey;  
}

export class EncryptionKeyPair implements KeyPair {
  public: EncryptionPublicKey;
  private: EncryptionPrivateKey;

  constructor(pub: Uint8Array | string, priv: Uint8Array | string) {
    this.private = {visibility:'private', type: 'encryption', key: (typeof priv === 'string') ? priv : fromByteArray(priv)};
    this.public = {visibility: 'public', type: 'encryption', key: (typeof pub === 'string') ? pub : fromByteArray(pub)};
  }
  /**
   * returns a non-type safe keypair that can be easily plugged into any tweetnacl function.
   * @returns {BoxKeypair} tweetnacl keypair.
   */
  toBoxKeyPair = (): BoxKeyPair => {
    return {
      publicKey: toByteArray(this.public.key),
      secretKey: toByteArray(this.private.key),
    }
  }
}

export class SigningKeyPair implements KeyPair {
  public: SigningPublicKey;
  private: SigningPrivateKey;

  constructor(pub: Uint8Array | string, priv: Uint8Array | string) {
    this.private = {visibility:'private', type: 'signing', key: (typeof priv === 'string') ? priv : fromByteArray(priv)};
    this.public = {visibility: 'public', type: 'signing', key: (typeof pub === 'string') ? pub : fromByteArray(pub)};
  }

  /**
   * returns a non-type safe keypair that can be easily plugged into any tweetnacl function.
   * @returns {BoxKeypair} tweetnacl keypair.
   */
  toSignKeyPair = (): SignKeyPair => {
    return {
      publicKey: toByteArray(this.public.key),
      secretKey: toByteArray(this.private.key),
    }
  }
}

export interface TypedEncryptionPublicKey<T extends String> extends EncryptionPublicKey {
  subtype: T
}

export interface TypedEncryptionPrivateKey<T extends String> extends EncryptionPrivateKey {
  subtype: T
}

export class TypedEncryptionKeyPair<T extends String> extends EncryptionKeyPair {
  public: TypedEncryptionPublicKey<T>;
  private: TypedEncryptionPrivateKey<T>;

  constructor(pub: Uint8Array | string, priv: Uint8Array | string, subtype: T) {
    super(pub, priv);
    this.private = {visibility: 'private', type: 'encryption', subtype, key: (typeof priv === 'string') ? priv : fromByteArray(priv)};
    this.public = {visibility: 'public', type: 'encryption', subtype, key: (typeof pub === 'string') ? pub : fromByteArray(pub)};
  }
}

export interface TypedSigningPublicKey<T extends String> extends SigningPublicKey {
  subtype: T
}

export interface TypedSigningPrivateKey<T extends String> extends SigningPrivateKey {
  subtype: T
}

export class TypedSigningKeyPair<T extends String> extends SigningKeyPair {
  public: TypedSigningPublicKey<T>;
  private: TypedSigningPrivateKey<T>;

  constructor(pub: Uint8Array | string, priv: Uint8Array | string, subtype: T) {
    super(pub, priv);
    this.private = {visibility: 'private', type: 'signing', subtype, key: (typeof priv === 'string') ? priv : fromByteArray(priv)};
    this.public = {visibility: 'public', type: 'signing', subtype, key: (typeof pub === 'string') ? pub : fromByteArray(pub)};
  }
}

/**
 * Generates a Symmetric encryption key.
 * @returns {SymmetricKey} a random key used for Symmetric encryption.
 */
export function generateSymmetricKey(): SymmetricKey {
  return nacl.randomBytes(nacl.secretbox.keyLength);
}

/**
 * Generates a nonce (a single use number) to be used for encryption.
 * @returns {Nonce} random string of bytes.
 */
export function generateNonce(): Nonce {
  return nacl.randomBytes(nacl.secretbox.nonceLength);
}

/**
 * 
 * @returns {EncryptionKeyPair} Keypair used for encryption.
 */
export function generateEncryptionKeyPair(): EncryptionKeyPair {
  const keypair = nacl.box.keyPair();
  return new EncryptionKeyPair(keypair.publicKey, keypair.secretKey);
}

/**
 * 
 * @returns {SigningKeyPair} Keypair used for signing.
 */
export function generateSigningKeyPair(): SigningKeyPair {
  const signingKeypair = nacl.sign.keyPair();
  return new SigningKeyPair(signingKeypair.publicKey, signingKeypair.secretKey);
}

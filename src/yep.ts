import { fromByteArray, toByteArray } from "base64-js"
import { AEAD, DatagramCodec, DatagramMetadata, EncryptedDatagram, EncryptionKeyPair, EncryptionPrivateKey, EncryptionPublicKey, KeyPair, PrivateKey, PublicKey, SigningPrivateKey, SigningPublicKey, SymmetricKey, computeSharedKey, generateSymmetricKey } from "./crypto"
import nacl, { BoxKeyPair } from "tweetnacl"
import { SymmetricKeyDatagramCodec, SymmetricKeyDatagramMetadata, createJsonDatagramCodec } from "./codec"

export type PermissionSecret<Name extends string> = { name: Name, key: SymmetricKey };

export interface PermissionPublicKey<Name extends string> extends EncryptionPublicKey {
  name: Name,
  subtype: 'permission'
}
export interface PermissionPrivateKey<Name extends string> extends EncryptionPrivateKey {
  name: Name,
  subtype: 'permission'
}

export interface ServicePublicKey extends EncryptionPublicKey {
  subtype: 'service'
}
export interface ServicePrivateKey extends EncryptionPrivateKey {
  subtype: 'service'
}

type PermissionDataType<Keys extends string> = { [Key in Keys]: PermissionPrivateKey<Key> };
export type PermissionData<Keys extends string, Name extends string> = { privateKey: PermissionPrivateKey<Name>, data: PermissionDataType<Keys>};

export interface PermissionDataDatagramMetadata<Name extends string> extends DatagramMetadata {
  type: `datagram://permission_${Name}`;
  version: '0.1.0';
}


export type Permission<Keys extends string, Name extends string> = {
  name: Name,
  publicKey: PermissionPublicKey<Name>,
  privateData: EncryptedDatagram<PermissionData<Keys, Name> ,PermissionDataDatagramMetadata<Name>>;
}

export type PermissionGrant<Name extends string> = { name: Name, grantKey: EncryptedDatagram<SymmetricKey, SymmetricKeyDatagramMetadata> };
export type PermissionProof<Name extends string> = { name: Name, proofKey: EncryptedDatagram<SymmetricKey, SymmetricKeyDatagramMetadata> };

export class YEP {

  private static getCodec<Keys extends string, T extends PermissionDataType<Keys>,Name extends string>(name: Name): DatagramCodec<PermissionData<Keys, Name>, PermissionDataDatagramMetadata<Name>> {
    const datagramMetadata: PermissionDataDatagramMetadata<Name> = {
      type: `datagram://permission_${name}`,
      version: '0.1.0'
    };
    return createJsonDatagramCodec(datagramMetadata);
  }

  private static getPermissionSecretFromGrant<Name extends string>(grant: PermissionGrant<Name>, myPrivateKey: EncryptionPrivateKey): PermissionSecret<Name> {
    return { name: grant.name, key: AEAD.unseal(grant.grantKey, SymmetricKeyDatagramCodec, myPrivateKey)};
  }

  static newPermission<Keys extends string, Name extends string>(name: Name, data: PermissionDataType<Keys>, myPublicKey: EncryptionPublicKey): { permission: Permission<Keys, Name>, keys:PermissionKeyPair<Name>, grant: PermissionGrant<Name> } {
    const permissionKeyPair = generatePermissionKeyPair(name);
    const permissionSecret = generateSymmetricKey();
    const permissionData: PermissionData<Keys, Name> = { privateKey: permissionKeyPair.private, data };
    const privateData = AEAD.encryptSymmetric(permissionData, YEP.getCodec(name), permissionSecret);
    return { permission: { name, publicKey: permissionKeyPair.public, privateData }, keys: permissionKeyPair, grant: {name, grantKey: AEAD.seal(permissionSecret, SymmetricKeyDatagramCodec, myPublicKey) }};
  }

  static createGrant<Name extends string>(myPrivateKey: EncryptionPrivateKey, myPermissionGrant: PermissionGrant<Name>, theirPublicKey: EncryptionPublicKey) : PermissionGrant<Name> {
    return {name: myPermissionGrant.name, grantKey: AEAD.seal(AEAD.unseal(myPermissionGrant.grantKey, SymmetricKeyDatagramCodec, myPrivateKey), SymmetricKeyDatagramCodec, theirPublicKey)};
  }

  static createProof<Keys extends string, Name extends string>(
      permission: Permission<Keys, Name>,
      myPermissionGrant: PermissionGrant<Name>,
      myPrivateKey: EncryptionPrivateKey,
      mySigningKey: SigningPrivateKey,
      servicePublicKey: ServicePublicKey): PermissionProof<Name> {
    const permissionData = AEAD.decryptSymmetric(permission.privateData, YEP.getCodec(permission.name), YEP.getPermissionSecretFromGrant(myPermissionGrant, myPrivateKey).key);
    const proofKey = AEAD.encryptAsymmetric(
      computeSharedKey(servicePublicKey, permissionData.privateKey),
      SymmetricKeyDatagramCodec,
      myPrivateKey,
      servicePublicKey,
      mySigningKey);
    return { name: permission.name, proofKey };
  }

  static createProofFor<Keys extends string, Name extends string, ProofName extends Keys>(
      name: ProofName,
      permission: Permission<Keys, Name>,
      myPermissionGrant: PermissionGrant<Name>,
      myPrivateKey: EncryptionPrivateKey,
      mySigningKey: SigningPrivateKey,
      servicePublicKey: ServicePublicKey ): PermissionProof<ProofName> {
    const permissionData = AEAD.decryptSymmetric(permission.privateData, YEP.getCodec(permission.name), YEP.getPermissionSecretFromGrant(myPermissionGrant, myPrivateKey).key);
    const proofKey = AEAD.encryptAsymmetric(
      computeSharedKey(servicePublicKey, permissionData.data[name]),
      SymmetricKeyDatagramCodec,
      myPrivateKey,
      servicePublicKey,
      mySigningKey);
    return { name, proofKey };
  }

  static verifyProof<Name extends string>(permission: Permission<string,Name>, proof: PermissionProof<Name>, userPublicKey: EncryptionPublicKey, userSigningPublicKey: SigningPublicKey, servicePrivateKey: ServicePrivateKey): boolean {
    const computedKey = computeSharedKey(permission.publicKey, servicePrivateKey);
    return fromByteArray(
      AEAD.decryptAsymmetric(
        proof.proofKey,
        SymmetricKeyDatagramCodec,
        servicePrivateKey,
        userPublicKey,
        userSigningPublicKey
      )) === fromByteArray(computedKey);
  }
}

export class PermissionKeyPair<Name extends string> implements KeyPair {
  public: PermissionPublicKey<Name>;
  private: PermissionPrivateKey<Name>;

  constructor(name: Name, pub: Uint8Array | string, priv: Uint8Array | string) {
    this.private = {name, visibility:'private', type: 'encryption', subtype: 'permission', key: (typeof priv === 'string') ? priv : fromByteArray(priv)};
    this.public = {name, visibility: 'public', type: 'encryption', subtype: 'permission', key: (typeof pub === 'string') ? pub : fromByteArray(pub)};
  }

  /**
   * returns a non-type safe keypair that can be easily plugged into any tweetnacl function.
   * @returns {BoxKeypair} tweetnacl keypair.
   */
  static toBoxKeyPair<Name extends string>(keypair: PermissionKeyPair<Name>): BoxKeyPair {
    return {
      publicKey: toByteArray(keypair.public.key),
      secretKey: toByteArray(keypair.private.key),
    }
  }

  static toEncryptionKeyPair<Name extends string>(keypair: PermissionKeyPair<Name>): EncryptionKeyPair {
    return new EncryptionKeyPair(keypair.public.key, keypair.private.key);
  }
}

export class ServiceKeyPair implements KeyPair {
  public: ServicePublicKey;
  private: ServicePrivateKey;

  constructor(pub: Uint8Array | string, priv: Uint8Array | string) {
    this.private = {visibility:'private', type: 'encryption', subtype: 'service', key: (typeof priv === 'string') ? priv : fromByteArray(priv)};
    this.public = {visibility: 'public', type: 'encryption', subtype: 'service', key: (typeof pub === 'string') ? pub : fromByteArray(pub)};
  }

  /**
   * returns a non-type safe keypair that can be easily plugged into any tweetnacl function.
   * @returns {BoxKeypair} tweetnacl keypair.
   */
  static toBoxKeyPair = (keypair: ServiceKeyPair): BoxKeyPair => {
    return {
      publicKey: toByteArray(keypair.public.key),
      secretKey: toByteArray(keypair.private.key),
    }
  }

  static toEncryptionKeyPair = (keypair: ServiceKeyPair): EncryptionKeyPair => {
    return new EncryptionKeyPair(keypair.public.key, keypair.private.key);
  }
}

/**
 * @returns {PermissionKeyPair} Keypair used for permission.
 */
export function generatePermissionKeyPair<Name extends string>(name: Name): PermissionKeyPair<Name> {
  const permKeypair = nacl.box.keyPair();
  return new PermissionKeyPair(name, permKeypair.publicKey, permKeypair.secretKey);
}

/**
 * @returns {ServiceKeyPair} Keypair used for permission.
 */
export function generateServiceKeyPair(): ServiceKeyPair {
  const permKeypair = nacl.box.keyPair();
  return new ServiceKeyPair(permKeypair.publicKey, permKeypair.secretKey);
}

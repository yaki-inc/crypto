![Logo](https://yaki.company/yaki-crypto.svg)
# `@yaki-inc/crypto`

✅ Strongly typed
✅ Easy-to-use
✅ Battle tested encryption

Yaki, Inc's crypto library is built atop the popular and widely used [tweetnacl][tweetnacl] library. Tweetnacl is great, but developers can get easily lost with all the different kinds of keys involved.

There are public keys, secret keys, symmetric keys, encrypted bytes, unit8arrays passed over the wire as base64, and on and on... All represented as javascript strings. It is very easy to get stuck in debugland. Or worse yet, it's very easy to accidentally post a client secret key to the backend API end point and leak your keys to some unencrypted access.log file on a server :(

 This is a problem we faced while developing [Datayaki][datayaki].
 
 `@yaki-inc/crypto` solves for that by introducing typed jsoon primitives for all of those, and a strongly typed API to go along with them. We define the following primitives for cryptography. These ensure that a private key is never leaked in place of a public key, and that a signing key and encryption key aren't mixed up.
```tsx
export type SymmetricKey = Uint8Array;
export type Nonce = Uint8Array;
export type PublicKey = { visibility: 'public', type: string, key: string };
export type PrivateKey = { visibility: 'private', type: string, key: string };

export interface KeyPair {
  public: PublicKey;
  private: PrivateKey;  
}

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
```

In addition, we have a typed AEAD class inspired by `skiff-crypto`, but made a bit easier to understand and extend. To support typed encrypted data, we introduce three new interfaces:
```tsx
/**
 * DatagramMetadata - Type and version information.
 */
export interface DatagramMetadata {
  type: string;
  version: string; // Semver
}
```
```tsx
/**
 * DatagramCodec - Codec for serializing/deserializing datagrams for cryptography.
 */
export interface DatagramCodec<T, M extends DatagramMetadata>{
  metadata: M;
  versionRange: Range;
  serialize(data: T): Uint8Array;
  deserialize(bytes: Uint8Array): T;
}
```
```tsx
/**
 * EncryptedDatagram - Typed encrypted AEAD object.
 * Easily serializable/deserializable as JSON for use over wire.
 */
export interface EncryptedDatagram<T, M extends DatagramMetadata> {
  payload: string; // base64 encoded encrypted bytes.
  metadata: M;
};
```

The DatagramMetadata provides the type and versioning info, and the DatagramCodec provides the serialization/deserialization logic, and also specify which range of versions they are compatible with. So, if your codec only supports v2.0+ of your custom document model, but a v1.0 doc gets sent to your decryption logic, you can handle it gracefully.

We also provide readymade codecs and metadata types for simple JS primitive types such as strings and numbers. `StringDatagramMetadata`, `StringDatagramCodec`, `NumberDatagramMetadata`, `NumberDatagramCodec`, `SymmetricKeyDatagramMetadata`, `SymmetricKeyDatagramCodec` (for use in End-to-end encryption applications.) and provide a helper to quickly create a codec for typed JSON objects:

```tsx
export const createJsonDatagramCodec = <T, M extends DatagramMetadata(metadata: M, versionRange: Range = new Range('00.1.*'): DatagramCodec<T,M> => {...}
```

You can see how these can be used to encrypt in a type-safe manner below.

### Symmetric Encryption

Symmetric encryption uses a symmetric key, which as the name suggests, allows the same key to be used for both encryption and decryption. In symmetric key encryption, data is encrypted using a key to produce a ciphertext. Then the same key is used to decrypt the ciphertext and access the data again.

In our library `SymmetricKey` is synonympus with a `string`.

```tsx
import { generateSymmetricKey, AEAD, EncryptedDatagram, StringDatagramCodec } from `@yaki-inc/crypto`

const data = 'Hello World!';
const key = generateSymmetricKey();
const cipher: EncryptedDatagram<string, StringDatagramMetadata> = AEAD.encryptSymmetric(data, StringDatagramCodec, symmetricKey);
assertEquals(data, AEAD.decryptSymmetric(ciphertext, StringDatagramCodec, symmetricKey));

// ❌ The following will throw a TypeError.
assertEquals(data, AEAD.decryptSymmetric(cipher, NumberDatagramCodec, key));
```

There are many algorithms available for symmetric encryption. Datayaki uses the tweetnacl standard AES.

### Asymmetric Encryption - Seal/Unseal

Asymmetric Encryption, aka Public Key Encryption, uses a pair of complementary keys to encrypt and decrypt data. The user generates a key pair — a public key and a private key — instead of a single key, where data encrypted using one of the keys can only be decrypted using the other complementary key in the key pair. The public key can be shared with other parties, while the private key is kept secret and never shared. Public key encryption is how most messaging on the internet works, including HTTPS and SSL.

The following example also shows how you would work with strongly typed JSON objects.

```tsx
import { generateEncryptionKeyPair, AEAD } from `@yaki-inc/crypto`

const alice = yc.generateEncryptionKeyPair();
type TestType = {
  name: string,
  age: number,
  gender: 'M' | 'F' | 'N',
  birthday: Date,
  gigantor: BigInt
};
const testObject: TestType = {
  name: 'Alice',
  age: 25,
  gender: 'F',
  birthday: new Date(),
  gigantor: BigInt('12345678901234567890')
};
type TestMetadata = { type: 'datagram://json/test', version: '0.1.0'}; // Define a metadata type for your object.
const testMetadata: TestMetadata = { type: 'datagram://json/test', version: '0.1.0'};
const testCodec = yc.createJsonDatagramCodec<TestType, TestMetadata>(testMetadata); // Create a codec for your type.

const sealedbox = yc.AEAD.seal(testObject, testCodec, alice.public); // sealedbox's inferred type is EncryptedDatagram<TestType, TestMetadata>
const unsealedData = yc.AEAD.unseal(sealedbox, testCodec, alice.private);
expect(unsealedData).toEqual(testObject);
```

### Diffie Hellman Key Exchange (DHKE)

DH Key Exchange is a method for two parties to agree on a common symmetric encryption key using their Asymmetric Encryption Key Pairs, without exposing either party’s private key. This is the more common use case of Asymmetric Encryption. Thus in our library, the seldom used simpler asymmetric encryption is termed `seal`/`unseal` following the nomenclature used by `lisodium`, while the more common DHKE based encrypted communication scheme is termed `encryptAsymmetric`/`decryptAsymmetric`.

One of the interesting properties of Public/Private Asymmetric encryption is that given two parties Alice and Bob (or Client and Server), you can compute a shared Symmetric Key by combine one party’s Private Key with the other party’s Public Key, and it doesn’t matter which party’s private key or public key is used, you will arrive at the same shared Symmetric Key.

```tsx
const alice = generateEncryptionKeyPair();
const aliceSign = generateSigningKeyPair();
const bob = generateEncryptionKeyPair();
const testString = 'This is a test message';
const encrypted = AEAD.encryptAsymmetric(testString, StringDatagramCodec, alice.private, bob.public, aliceSign.private);
const decrypted = AEAD.decryptAsymmetric(encrypted, StringDatagramCodec, bob.private, alice.public, aliceSign.public);
expect(testString).toEqual(decrypted);
```

As you can see from above, both parties can agree on a shared symmetric encryption key without sharing their private keys, as long as they have access to the other’s public key.

As seen above, we also insist that DHKE encrypted ciphers are signed by the sender, and that the signature is verified by the recipient. This is just good practice, and we have chosen to enforce it.

We also export the following function to compute just the shared key as well:
```tsx
export function computeSharedKey(theirPublicKey: EncryptionPublicKey, myPrivateKey: EncryptionPrivateKey): SymmetricKey
```

> Note: We also provide API to optionally sign and verify symmetrically encrypted datagrams as well using `AEAD.signAndEncryptSymmetric`, and `AEAD.decryptSymmetricAndVerify` functions.

# Yaki Encryption Stack

In addition to above helpful type safe APIs, Yaki, Inc has developed bespoke encryption protocols that are built atop the foundational cryptographic methods described above. The stack mainly comprises of two major protocols, and are made available as part of the open source `@yaki-inc/crypto` and the soon to be released `@e2e2/client`  npm packages.

This package includes **YEP**, a bespoke protocol that allows you to provably authorize access and user permissions using cryptographic keys and DHKE. And soon, once `@e2e2` is published along with the launch of https://E2E2.me service, it will also include **CAKE** protocol, another bespoke protocol that bring OAuth-like authorization flows to the End-to-end encrypted web. At which point, we may separate out the yaki encryption stack (YEP and CAKE) into its own package. But that will have to wait...

## YEP Protocol

In [Datayaki][datayaki]’s privacy first collaboration platform, Roles and Permissions are also granted and verified in an end-to-end encrypted manner. **Yaki Encrypted Permissions** guarantees that permissions can only be granted by authorized parties and are safe from unauthorized parties manually injecting user authorizations within a service.

YEP works as follows:

- Permissions are represented by a public/private key-pair, also known as **PermissionKeys**.
    - PermissionKeys are granular. i.e, there is a key-pair per permission per resource.
        
        ```tsx
        PermissionKey(VIEW,Doc1) ≠ PermissionKey(VIEW,Doc2) ≠ PermissionKey(EDIT,Doc1)
        ```
        
    - PermissionKeys are generated by the user while creating the resource they guard.
    - The public key is called **PermissionPublicKey** (**PPK).**
    - the private key and any additional metadata is considered **PermissionPrivateData** (**PPD)**.
- The PPK is accessible to all, including Datayaki’s backend while the PPD is stored encrypted on the server using a Symmetric Key known as **PermissionSecretKey** (**PSK)**, that is only known to those authorized.
- Initially, only the user that created the Permission has access to its PSK as they create it and use it to encrypt the PPD.

**Granting Permissions**

- An authorized user, A, who has access to the PSK of Permission P is then allowed to authorize another user, B, by sharing the PSK with them by asymmetrically encrypting it with B’s public key. This encrypted asymmetrically encrypted PSK is called the **Permission Grant Key** or **PGK**. B can then decrypt the PGK and using their private key to gain access to PSK. This allows them to now read P’s private data or PPD.
- The authorized users (A or B) can now prove to the Service (Datayaki) that they are authorized with permission P by computing a shared key using the service’s public key and the private key found within P’s PPD, and sending that shared key asymmetrically encrypted with their private key as proof or permission.
    
    ```tsx
    const permissionProof = asymmetricEncrypt(computeSharedKey(permissionPrivateKey,servicePublicKey),userPrivateKey)
    ```
    

**Verifying Access**

- The service can then verify that the user has been authorized for P by computing a shared key with its own private key and the permission P’s public key (PPK) and verifying it against the proof the user sent.
    
    ```tsx
    const sharedKeyFromProof = decryptAsymmetric(permissionProof, userPublicKey);
    const computedSharedKey = computeSharedKey(servicePrivateKey, permissionPublicKey);
    assertEquals(sharedKeyFromProof, computedSharedKey);
    ```
    

As you can see from above, this protocol comes with a few nice desirable traits.

- Proof of authorization simply involves proving to the service that user has access to PSK, and thus the PPD.
- Neither information about the PSK nor information about the PPD is divulged to the service or to MITM as only information the service can already compute on its own, i.e shared key is sent.
- Unauthorized personnel are prevented from authorizing users by manipulating records on the server, as only authorized personnel who already have access to PSK can share it with other users. So, a database admin can’t simply go set a flag to enable access to an unauthorized user.
- Since each user has a unique PGK minted for their use, A MITM / Replay attack does not allow an unauthorized party to gain permission via database record manipulation.

> **Note:** In YEP, the permission’s secret key is shared with all authorized users. This is essential to allow users to authorize one another and pass on permission rights. This is different from CAKE, another Yaki protocol which will be published soon will have centralized authorization where no one has access to the secret keys of any other parties, but in that case, the protocol solves for OAuth-esque flow for authn/authz in the end-to-end encrypted web.

Another thing to note is that the permissions themselves are simply public-key / private-data objects and don’t come with any logical restrictions, and it is up to the service to implement any restrictions based on the authorizations the user possesses. This allows for flexibility in the kinds of access control mechanisms that can be implemented.

For example, the service that holds a repository of user's permission grants can also require the authorized user of a permission, say `VIEW_DOC1`, to possess additional permission such as `SHARE_DOC1` to be able to share permission secrets with other users.

> **Note:** The protocol itself is neutral to service implementation, and can be easily extended and made more restrictive with additional service logic.

Of course, nothing prevents an unauthorized user without a `SHARE_DOC1` permission from granting a PGK for another user and sharing it off-channel. For this reason, if the service cares about the means by which a user attained their grant, then the should maintain a repository of grants for the user and verify against it to be sure that access was granted through legitimate means.

**Revoking Permissions**

Revoking permissions can be done in two ways:

1. Rotating the permission keys and minting new grants for every other user.
  
   > But this operation scales linearly with the number of active users, and may not be desireable, even though it guarantees the most security. And, for the cost, you gain the ability to perform access checks in a decentralized fashion.

2. By maintaining a repository of grants as mentioned earlier, and simply removing the PGK record for a specific user. This would allow the service to fail validation even though the user might present a valid proof.

   > Although this is a O(1) operation, this comes at the cost of weakened security as unauthorized parties now have access to the PSK. It also comes at the cost of not being able to verify access in a decentralized fashion.

Ideally, you would perform both steps so that access revocation can be quick by performing (2) first, and then you can kick off a process to asynchronously rotate keys and grants.

**Security Risks & Guarantees**

YEP, like any other security protocol, has it's pros and cons.

- For instance, a malicious user that had once been granted a permission and later had their access revoked could potentially hack into the database and insert their old PGK and regain access.
    
    This can be mitigated by the server implementing additional measures such as generating a signed audit log for each user and verifying against the actions performed on the user’s log to ensure that they didn’t have their access revoked, but this is such a far-off remote possibility that Datayaki deems it enough to validate the cryptographic permission proof and to check for existence of PGK record to allow a user. That is already orders of magnitude better than any existing flag based permissioning system.
    
- Another issue is that a malicious hacker or an unintentional db admin error could delete PGK records from the database and revoke permissions for legitimate users.
    
    This can be mitigated through database backups, and in Datayaki’s case, following Local First (LoFi) development standards and caching the PGKs on the client side for each user. Especially for those with ADMIN rights, such that access to entire organization’s worth of data and permissions isn’t lost permanently.

- YEP by itself guarantees protection against unauthorized “Escalation of Privileges”.
- but YEP also introduces the risk of unintended “Denial of Service”, which can be mitigated through LoFi caching and recovery mechanisms such as database backups, as is the case with Datayaki.

# YEP API

See yep.test.ts for examples of how to implement YEP in your code. But the key concepts to pay attention to are:
* `Permission` - An object that holds and represents a granular permission as a keypair.
* `Grant` - An authorization to enable that permission.
* `Proof` - A cryptographic proof that can be used by a service to know that you have been granted the permission.

## Creating a permission

```tsx
YEP.newPermission<Keys extends string, Name extends string>(
  name: Name,
  data:  PermissionDataType<Keys>,
  creatorPublicKey: PublicKey): { permission: Permission<Name>, keys: PermissionKeyPair<Name>, grant: PermissionGrant<Name>};
```
`Keys` and `PermissionDataType` are used for complex permissions where granting one permission should also include grants for other permissions. For example, a document's  `Edit` permission should also include grants for `View` and `Comment` in that document. For the simple use case, where a permission only manages access to a single use case, you would simply call:

```tsx
const { permission: viewPerm, keys: viewPermKeys, grant: viewGrant } = YEP.newPermission('VIEW',{},myKeys.public);
```

For complex permissions, you would have to create the simple ones first, and include their keys in the `data` object for the complex permission.

```tsx
    const {permission: viewPermission, keys: viewKeys, grant: viewGrant} = YEP.newPermission('VIEW', {}, alice.public);
    const {permission: commentPermission, keys: commentKeys, grant: commentGrant} = YEP.newPermission('COMMENT', { 'VIEW', viewKeys.private }, alice.public);
    const {permission: editPermission, keys: editKeys, grant: editGrant} = YEP.newPermission('EDIT', { 'VIEW': viewKeys.private, 'COMMENT': commentKeys.private }, alice.public);
```

As you can see, the creator will automatically have a grant generated for them, and it is important to save this, as it is needed to grant others access to that permission.

**IMPORTANT:** Permissions can only be granted by those who have already been granted permissions.

## Granting permission

```tsx
YEP.createGrant<Name extends string>(
  myPrivateKey: EncryptionPrivateKey,
  myPermissionGrant: PermissionGrant<Name>,
  theirPublicKey: EncryptionPublicKey) : PermissionGrant<Name>
```
The grantor will need their permission grant, their private key, and the grantee's public key to issue a new grant for the other party.

## Proving access

```tsx
YEP.createProof<Keys extends string, Name extends string>(
  permission: Permission<Keys, Name>,
  myPermissionGrant: PermissionGrant<Name>,
  myPrivateKey: EncryptionPrivateKey,
  mySigningKey: SigningPrivateKey,
  servicePublicKey: ServicePublicKey): PermissionProof<Name>
```

In case of a complex permission, such as the document edit permission, you can prove access to a subkey by using `YEP.createProofFor(...)`, which
also takes in the permission name as its first parameter.

```tsx
YEP.createProofFor<Keys extends string, Name extends string, ProofName extends Keys>(
      name: ProofName,
      permission: Permission<Keys, Name>,
      myPermissionGrant: PermissionGrant<Name>,
      myPrivateKey: EncryptionPrivateKey,
      mySigningKey: SigningPrivateKey,
      servicePublicKey: ServicePublicKey ): PermissionProof<ProofName>
```

## Verifying the PermissionProof

This check is performed by the service to which a user provided a proof. Returns true if and only if the provided proof is a valid proof for the permission.

```tsx
YEP.verifyProof<Name extends string>(
  permission: Permission<string,Name>,
  proof: PermissionProof<Name>,
  userPublicKey: EncryptionPublicKey,
  userSigningPublicKey: SigningPublicKey,
  servicePrivateKey: ServicePrivateKey): boolean
```
***

[datayaki]: https://datayaki.com
[tweetnacl]: https://www.npmjs.com/package/tweetnacl
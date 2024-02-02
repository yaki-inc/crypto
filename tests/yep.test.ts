import { generateEncryptionKeyPair, generateSigningKeyPair } from "../src";
import { YEP, generateServiceKeyPair } from "../src/yep";

describe('Test YEP permissions', () => {
  it('create new basic permission and test proof and verification', async () => {
    const alice = generateEncryptionKeyPair();
    const aSign = generateSigningKeyPair();
    const service = generateServiceKeyPair();
    const {permission, grant} = YEP.newPermission('VIEW', {}, alice.public);
    const proof = YEP.createProof(permission, grant, alice.private, aSign.private, service.public);
    const verification = YEP.verifyProof(permission, proof, alice.public, aSign.public, service.private);
    expect(verification).toBe(true);
  });

  it('create new complex permission and test proof and verification', async () => {
    const alice = generateEncryptionKeyPair();
    const aSign = generateSigningKeyPair();
    const service = generateServiceKeyPair();
    const {permission: viewPermission, keys: viewKeys, grant: viewGrant} = YEP.newPermission('VIEW', {}, alice.public);
    const {permission: editPermission, keys: editKeys, grant: editGrant} = YEP.newPermission('EDIT', { 'VIEW': viewKeys.private}, alice.public);
    const editProof = YEP.createProof(editPermission, editGrant, alice.private, aSign.private, service.public);
    const editVerification = YEP.verifyProof(editPermission, editProof, alice.public, aSign.public, service.private);
    expect(editVerification).toBe(true);
    const viewProof = YEP.createProof(viewPermission, viewGrant, alice.private, aSign.private, service.public);
    const viewVerification = YEP.verifyProof(viewPermission, viewProof, alice.public, aSign.public, service.private);
    expect(viewVerification).toBe(true);
    const complexViewProof = YEP.createProofFor('VIEW', editPermission, editGrant, alice.private, aSign.private, service.public);
    const complexViewVerification = YEP.verifyProof(viewPermission, complexViewProof, alice.public, aSign.public, service.private);
    expect(complexViewVerification).toBe(true);
  });

  it('Grant permission and test proof and verification', async () => {
    const alice = generateEncryptionKeyPair();
    const aSign = generateSigningKeyPair();
    const bob = generateEncryptionKeyPair();
    const bSign = generateSigningKeyPair();
    const service = generateServiceKeyPair();
    const {permission, grant: aliceGrant} = YEP.newPermission('VIEW', {}, alice.public);
    const aliceProof = YEP.createProof(permission, aliceGrant, alice.private, aSign.private, service.public);
    const verification = YEP.verifyProof(permission, aliceProof, alice.public, aSign.public, service.private);
    expect(verification).toBe(true);
    const bobsGrant = YEP.createGrant(alice.private, aliceGrant, bob.public);
    const bobProof = YEP.createProof(permission, bobsGrant, bob.private, bSign.private, service.public);
    expect(bobProof).not.toEqual(aliceProof);
    expect(YEP.verifyProof(permission, bobProof, bob.public, bSign.public, service.private)).toBe(true);
  });
  
  it('produces unique proofs each time', async () => {
    const alice = generateEncryptionKeyPair();
    const aSign = generateSigningKeyPair();
    const service = generateServiceKeyPair();
    const {permission, grant} = YEP.newPermission('VIEW', {}, alice.public);
    const proof1 = YEP.createProof(permission, grant, alice.private, aSign.private, service.public);
    const verification1 = YEP.verifyProof(permission, proof1, alice.public, aSign.public, service.private);
    const proof2 = YEP.createProof(permission, grant, alice.private, aSign.private, service.public);
    const verification2 = YEP.verifyProof(permission, proof1, alice.public, aSign.public, service.private);
    expect(verification1).toBe(true);
    expect(verification2).toBe(true);
    expect(proof1).not.toEqual(proof2); // Proofs must be protected from replayability attacks.
  })

  it('fails on invalid grant', async () => {
    const alice = generateEncryptionKeyPair();
    const aSign = generateSigningKeyPair();
    const service = generateServiceKeyPair();
    const {permission: perm1, grant: grant1} = YEP.newPermission('VIEW', {}, alice.public);
    const {permission: perm2, grant: grant2} = YEP.newPermission('VIEW', {}, alice.public);
    const proof1 = YEP.createProof(perm1, grant1, alice.private, aSign.private, service.public);
    const verification1 = YEP.verifyProof(perm1, proof1, alice.public, aSign.public, service.private);
    const proof2 = YEP.createProof(perm2, grant2, alice.private, aSign.private, service.public);
    const verification2 = YEP.verifyProof(perm2, proof2, alice.public, aSign.public, service.private);
    expect(verification1).toBe(true);
    expect(verification2).toBe(true);
    expect(YEP.verifyProof(perm1, proof2, alice.public, aSign.public, service.private)).toBe(false);
    expect(YEP.verifyProof(perm2, proof1, alice.public, aSign.public, service.private)).toBe(false);
  })
})
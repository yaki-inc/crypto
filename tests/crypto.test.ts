import * as yc from '../src';
import { toByteArray, fromByteArray } from 'base64-js';

describe('test keypairs and symmetric keys', () => {
  it('generates keypairs', () => {
    const ekp: yc.EncryptionKeyPair = yc.generateEncryptionKeyPair();
    console.log('public: '+ekp.public.key);
    console.log('private: '+ekp.private.key);
    expect(ekp.public.type).toEqual('encryption');
    expect(ekp.public.visibility).toEqual('public');
    expect(ekp.private.type).toEqual('encryption');
    expect(ekp.private.visibility).toEqual('private');
  });

  it('generates signing keypairs', () => {
    const skp: yc.SigningKeyPair = yc.generateSigningKeyPair();
    console.log('public: '+skp.public.key);
    console.log('private: '+skp.private.key);
    expect(skp.public.type).toEqual('signing');
    expect(skp.public.visibility).toEqual('public');
    expect(skp.private.type).toEqual('signing');
    expect(skp.private.visibility).toEqual('private');
  });

  it('handles base64', () => {
    const ekp = new yc.EncryptionKeyPair('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE=','GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k=');
    expect(ekp.private.key).toEqual('GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k=');
    expect(ekp.public.key).toEqual('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE=');

    const skp = new yc.SigningKeyPair('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE=','GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k=');
    expect(skp.private.key).toEqual('GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k=');
    expect(skp.public.key).toEqual('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE=');

  });

  it('handles byteArrays', () => {
    const ekp = new yc.EncryptionKeyPair(toByteArray('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE='),toByteArray('GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k='));
    expect(ekp.private.key).toEqual('GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k=');
    expect(ekp.public.key).toEqual('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE=');

    const skp = new yc.SigningKeyPair(toByteArray('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE='),toByteArray('GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k='));
    expect(skp.private.key).toEqual('GlGYUfRn89zMWoUkbd+rv073lmKgjwvAgWlUqZE/58k=');
    expect(skp.public.key).toEqual('g46PX/GVdew9ox30sakMlIP1UJD8AJ02lFm3iv3eBRE=');
  });

});

describe('test salts and hashes', () => {
  it('generates nonce', () => {
    const nonce = yc.generateNonce();
    console.log('nonce: '+fromByteArray(nonce));
  })
})

describe('test AEAD', () => {
  it('encrypts and decrypts strings with Symmetric Keys', async () => {
    const sk: yc.SymmetricKey = yc.generateSymmetricKey();
    console.log('symmetric key: '+sk);
    const testString = 'abcdefg1234567';
    console.log('String for encryption: '+testString);
    const ed = yc.AEAD.encryptSymmetric(testString, yc.StringDatagramCodec, sk);
    console.log("EncryptedDatagram: "+JSON.stringify(ed));
    const decryptedString = yc.AEAD.decryptSymmetric(ed, yc.StringDatagramCodec, sk);
    console.log('decrypted string: '+decryptedString);
    expect(testString).toEqual(decryptedString);
  });

  it('Fails to decrypt strings with wrong Symmetric Keys', async () => {
    const esk: yc.SymmetricKey = yc.generateSymmetricKey();
    const dsk = yc.generateSymmetricKey();
    console.log('symmetric key: '+esk);
    const testString = 'abcdefg1234567';
    console.log('String for encryption: '+testString);
    const ed = yc.AEAD.encryptSymmetric(testString, yc.StringDatagramCodec, esk);
    console.log("EncryptedDatagram: "+JSON.stringify(ed));
    expect(() => yc.AEAD.decryptSymmetric(ed, yc.StringDatagramCodec, dsk)).toThrow();
  });

  it('encrypts and decrypts strings with Asymmetric Keys', async() => {
    const alice = yc.generateEncryptionKeyPair();
    const aliceSign = yc.generateSigningKeyPair();
    const bob = yc.generateEncryptionKeyPair();
    const testString = 'This is a test message';
    const encrypted = yc.AEAD.encryptAsymmetric(testString, yc.StringDatagramCodec, alice.private, bob.public, aliceSign.private);
    const decrypted = yc.AEAD.decryptAsymmetric(encrypted, yc.StringDatagramCodec, bob.private, alice.public, aliceSign.public);
    expect(testString).toEqual(decrypted);
    console.log('Asymmetric decrypted: '+decrypted);
  });

  it('encrypts and decrypts numbers with Symmetric Keys', async () => {
    const sk: yc.SymmetricKey = yc.generateSymmetricKey();
    console.log('symmetric key: '+sk);
    const testNumber = 123456789.23456;
    console.log('Number for encryption: '+testNumber);
    const ed = yc.AEAD.encryptSymmetric(testNumber, yc.NumberDatagramCodec, sk);
    console.log("EncryptedDatagram: "+JSON.stringify(ed));
    const decrypted = yc.AEAD.decryptSymmetric(ed, yc.NumberDatagramCodec, sk);
    console.log('decrypted number: '+decrypted);
    expect(testNumber).toEqual(decrypted);
  });

  it('Fails to decrypt if datagram metadata does not match', async () => {
    const sk: yc.SymmetricKey = yc.generateSymmetricKey();
    console.log('symmetric key: '+sk);
    const testNumber = 123456789.23456;
    console.log('Number for encryption: '+testNumber);
    const ed = yc.AEAD.encryptSymmetric(testNumber, yc.NumberDatagramCodec, sk);
    console.log("EncryptedDatagram: "+JSON.stringify(ed));
    expect(() => yc.AEAD.decryptSymmetric(ed as unknown as yc.EncryptedDatagram<string, yc.StringDatagramMetadata>, yc.StringDatagramCodec, sk)).toThrow();
  });

  it('Encrypts and Decrypts JSON Datagram guaranteeing type safety', async () => {
    const sk = yc.generateSymmetricKey();
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
    type TestMetadata = { type: 'datagram://json/test', version: '0.1.0'};
    const testMetadata: TestMetadata = { type: 'datagram://json/test', version: '0.1.0'};
    const testCodec = yc.createJsonDatagramCodec<TestType, TestMetadata>(testMetadata);

    const ed = yc.AEAD.encryptSymmetric(testObject, testCodec, sk);
    console.log(JSON.stringify(ed));
    const decrypted = yc.AEAD.decryptSymmetric(ed, testCodec, sk);
    expect(decrypted).toEqual(testObject);

    // Trying to use an incompatible codec to decrypt should fail.
    type AnotherMetadata = { type: 'datagram://json/AnotherType', version: '0.1.0'};
    const anotherMetadata: AnotherMetadata = { type: 'datagram://json/AnotherType', version: '0.1.0'};
    const anotherCodec = yc.createJsonDatagramCodec<TestType, AnotherMetadata>(anotherMetadata);
    expect(() => yc.AEAD.decryptSymmetric(ed as unknown as yc.EncryptedDatagram<TestType, AnotherMetadata>, anotherCodec, sk)).toThrow();

    // Trying to tamper the EncryptedDatagram's visible metadata should also not allow for this.
    const modifiedDatagram: yc.EncryptedDatagram<TestType, AnotherMetadata> = {...ed, metadata: anotherMetadata};
    expect(() => yc.AEAD.decryptSymmetric(modifiedDatagram, anotherCodec, sk)).toThrow();
  });
})

describe('test sealing and unsealing', () => {
  it('seals and unseals with valid keys', async () => {
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
    type TestMetadata = { type: 'datagram://json/test', version: '0.1.0'};
    const testMetadata: TestMetadata = { type: 'datagram://json/test', version: '0.1.0'};
    const testCodec = yc.createJsonDatagramCodec<TestType, TestMetadata>(testMetadata);

    const sealedbox = yc.AEAD.seal(testObject, testCodec, alice.public);
    const unsealedData = yc.AEAD.unseal(sealedbox, testCodec, alice.private);
    expect(unsealedData).toEqual(testObject);
  });
  it('fails to unseal with invalid keys', async () => {
    const alice = yc.generateEncryptionKeyPair();
    const bob = yc.generateEncryptionKeyPair();
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
    type TestMetadata = { type: 'datagram://json/test', version: '0.1.0'};
    const testMetadata: TestMetadata = { type: 'datagram://json/test', version: '0.1.0'};
    const testCodec = yc.createJsonDatagramCodec<TestType, TestMetadata>(testMetadata);

    const sealedbox = yc.AEAD.seal(testObject, testCodec, alice.public);
    expect(() => yc.AEAD.unseal(sealedbox, testCodec, bob.private)).toThrow();
  });
})

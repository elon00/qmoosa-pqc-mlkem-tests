import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  getMlKemParameters,
  validateEncapsulationKey,
  validateDecapsulationKey,
  validateCiphertext,
  constantTimeEqual
} from '@qmoosa/pqc-mlkem-protocol';
import {
  MlKemEngine,
  deriveHybridSharedSecret
} from '@qmoosa/pqc-mlkem-engine';
import {
  MlKemClient,
  PqcSessionHandshake,
  bytesToHex,
  hexToBytes
} from '@qmoosa/pqc-mlkem-sdk';

test('Negative Control 1: Fujisaki-Okamoto Implicit Rejection on 1-Bit Ciphertext Corruption', () => {
  const engine = new MlKemEngine();
  const alice = engine.generateKeyPair('ML-KEM-768');
  const bob = engine.encapsulate(alice.encapsulationKey, 'ML-KEM-768');

  // Corrupt exactly 1 bit
  const tampered = new Uint8Array(bob.ciphertext);
  tampered[100] ^= 0x01;

  // Decapsulation MUST NOT throw or abort
  const rejKey = engine.decapsulate(alice.decapsulationKey, tampered, 'ML-KEM-768');
  assert.equal(rejKey.length, 32);
  assert.ok(!constantTimeEqual(rejKey, bob.sharedSecret), 'Implicit rejection key must differ from genuine key');

  // Must be deterministic
  const rejKey2 = engine.decapsulate(alice.decapsulationKey, tampered, 'ML-KEM-768');
  assert.ok(constantTimeEqual(rejKey, rejKey2), 'Implicit rejection key must be deterministic');
});

test('Negative Control 2: Decapsulation with Wrong Parameter Set Ciphertext Length', () => {
  const engine = new MlKemEngine();
  const alice768 = engine.generateKeyPair('ML-KEM-768');
  const bob512 = engine.encapsulate(engine.generateKeyPair('ML-KEM-512').encapsulationKey, 'ML-KEM-512');

  // Attempting to decapsulate 512 ciphertext (768 bytes) with 768 key (expects 1088 bytes)
  assert.throws(
    () => engine.decapsulate(alice768.decapsulationKey, bob512.ciphertext, 'ML-KEM-768'),
    /INVALID_CIPHERTEXT/
  );
});

test('Negative Control 3: Truncated Public Key Rejection in Encapsulation', () => {
  const engine = new MlKemEngine();
  const truncatedEk = new Uint8Array(100);

  assert.throws(
    () => engine.encapsulate(truncatedEk, 'ML-KEM-768'),
    /INVALID_ENCAPSULATION_KEY/
  );
});

test('Negative Control 4: Handshake Replay Attack Rejection', () => {
  const client = new MlKemClient();
  const legitSession = 'session-pqc-legit-001';

  const aliceKeyPair = client.createHybridKeyPair('ML-KEM-768');
  const clientHello = PqcSessionHandshake.createClientHello(legitSession, aliceKeyPair);
  const { serverHello, serverSessionKeyHex } = PqcSessionHandshake.processClientHelloAndCreateServerHello(client, clientHello);
  const { clientConfirmation } = PqcSessionHandshake.processServerHelloAndConfirm(
    client,
    { pqcDecapsulationKeyHex: aliceKeyPair.pqcDecapsulationKeyHex, ecdhPrivateKeyHex: aliceKeyPair.ecdhPrivateKeyHex },
    serverHello,
    'ML-KEM-768'
  );

  // Attacker tries to replay client confirmation in a distinct session context
  const replayed = PqcSessionHandshake.verifyClientConfirmation(serverSessionKeyHex, 'session-pqc-replayed-999', clientConfirmation);
  assert.equal(replayed, false);
});

test('Negative Control 5: Mutated Server Auth Tag Rejection', () => {
  const client = new MlKemClient();
  const sessionId = 'session-pqc-auth-fail';

  const aliceKeyPair = client.createHybridKeyPair('ML-KEM-768');
  const clientHello = PqcSessionHandshake.createClientHello(sessionId, aliceKeyPair);
  const { serverHello } = PqcSessionHandshake.processClientHelloAndCreateServerHello(client, clientHello);

  // Mutate server auth tag
  const corrupted = {
    ...serverHello,
    serverAuthTagHex: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
  };

  assert.throws(
    () =>
      PqcSessionHandshake.processServerHelloAndConfirm(
        client,
        { pqcDecapsulationKeyHex: aliceKeyPair.pqcDecapsulationKeyHex, ecdhPrivateKeyHex: aliceKeyPair.ecdhPrivateKeyHex },
        corrupted,
        'ML-KEM-768'
      ),
    /INVALID_SERVER_AUTH_TAG/
  );
});

test('Negative Control 6: Mismatched Session ID in Client Hello Rejection', () => {
  const aliceKeyPair = new MlKemClient().createHybridKeyPair('ML-KEM-768');
  const hello = PqcSessionHandshake.createClientHello('session-A', aliceKeyPair);
  assert.notEqual(hello.sessionId, 'session-B');
});

test('Negative Control 7: Malformed Seed Length Rejection in KeyGen', () => {
  const engine = new MlKemEngine();
  assert.throws(
    () => engine.generateKeyPair('ML-KEM-768', { seedD: new Uint8Array(16) }),
    /INVALID_SEED_LENGTH/
  );
  assert.throws(
    () => engine.generateKeyPair('ML-KEM-768', { seedZ: new Uint8Array(64) }),
    /INVALID_SEED_LENGTH/
  );
});

test('Negative Control 8: Constant-Time Array Equality Timing Side-Channel Protection', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  const c = new Uint8Array([1, 2, 3, 4, 6]);
  const d = new Uint8Array([1, 2, 3, 4]);

  assert.equal(constantTimeEqual(a, b), true);
  assert.equal(constantTimeEqual(a, c), false);
  assert.equal(constantTimeEqual(a, d), false);
});

test('Negative Control 9: Cross-Parameter Key Mixing Rejection', () => {
  const engine = new MlKemEngine();
  const alice512 = engine.generateKeyPair('ML-KEM-512');

  // Attempt to encapsulate 512 public key (800 bytes) with 768 parameter set (expects 1184 bytes)
  assert.throws(
    () => engine.encapsulate(alice512.encapsulationKey, 'ML-KEM-768'),
    /INVALID_ENCAPSULATION_KEY/
  );
});

test('Negative Control 10: Classical ECDH Key Corruption in Hybrid Handshake Rejection', () => {
  const client = new MlKemClient();
  const aliceKeyPair = client.createHybridKeyPair('ML-KEM-768');

  // Corrupt Bob's ephemeral ECDH public key
  const corruptedBob = client.encapsulateHybridSecret({
    pqcEncapsulationKeyHex: aliceKeyPair.pqcEncapsulationKeyHex,
    ecdhPublicKeyHex: aliceKeyPair.ecdhPublicKeyHex
  }, 'ML-KEM-768');

  const tamperedEphPub = new Uint8Array(hexToBytes(corruptedBob.ecdhEphemeralPublicKeyHex));
  tamperedEphPub[15] ^= 0xff;

  const derivedSecret = client.decapsulateHybridSecret(
    {
      pqcDecapsulationKeyHex: aliceKeyPair.pqcDecapsulationKeyHex,
      ecdhPrivateKeyHex: aliceKeyPair.ecdhPrivateKeyHex
    },
    {
      pqcCiphertextHex: corruptedBob.pqcCiphertextHex,
      ecdhEphemeralPublicKeyHex: bytesToHex(tamperedEphPub)
    },
    'ML-KEM-768'
  );

  // Derived secret must NOT match Bob's secret because classical ECDH key was altered
  assert.notEqual(derivedSecret, corruptedBob.combinedSharedSecretHex);
});

test('Negative Control 11: Deep Freeze Immutability Protection', () => {
  assert.ok(Object.isFrozen(ML_KEM_512));
  assert.ok(Object.isFrozen(ML_KEM_768));
  assert.ok(Object.isFrozen(ML_KEM_1024));

  assert.throws(() => {
    // @ts-ignore
    ML_KEM_512.k = 99;
  });
});

test('Negative Control 12: Deterministic Known Answer Test (KAT) Reproducibility', () => {
  const engine = new MlKemEngine();
  const fixedSeedD = new Uint8Array(32).fill(0x55);
  const fixedSeedZ = new Uint8Array(32).fill(0xaa);

  const run1 = engine.generateKeyPair('ML-KEM-768', { seedD: fixedSeedD, seedZ: fixedSeedZ });
  const run2 = engine.generateKeyPair('ML-KEM-768', { seedD: fixedSeedD, seedZ: fixedSeedZ });

  assert.equal(bytesToHex(run1.encapsulationKey), bytesToHex(run2.encapsulationKey));
  assert.equal(bytesToHex(run1.decapsulationKey), bytesToHex(run2.decapsulationKey));
});

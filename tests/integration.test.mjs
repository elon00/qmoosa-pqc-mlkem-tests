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

test('Integration Reality: Cross-Subsystem End-to-End PQC Lifecycle', () => {
  const engine = new MlKemEngine();
  const client = new MlKemClient(engine);

  // 1. Verify parameter set compliance via protocol package
  const params768 = getMlKemParameters('ML-KEM-768');
  assert.equal(params768.k, 3);
  assert.equal(params768.encapsulationKeyBytes, 1184);

  // 2. Client generates hybrid keypair
  const alice = client.createHybridKeyPair('ML-KEM-768');
  assert.equal(validateEncapsulationKey(hexToBytes(alice.pqcEncapsulationKeyHex), params768), true);
  assert.equal(validateDecapsulationKey(hexToBytes(alice.pqcDecapsulationKeyHex), params768), true);

  // 3. Peer encapsulates hybrid key
  const bob = client.encapsulateHybridSecret({
    pqcEncapsulationKeyHex: alice.pqcEncapsulationKeyHex,
    ecdhPublicKeyHex: alice.ecdhPublicKeyHex
  }, 'ML-KEM-768');

  assert.equal(validateCiphertext(hexToBytes(bob.pqcCiphertextHex), params768), true);

  // 4. Client decapsulates hybrid key
  const aliceDerivedSecret = client.decapsulateHybridSecret({
    pqcDecapsulationKeyHex: alice.pqcDecapsulationKeyHex,
    ecdhPrivateKeyHex: alice.ecdhPrivateKeyHex
  }, {
    pqcCiphertextHex: bob.pqcCiphertextHex,
    ecdhEphemeralPublicKeyHex: bob.ecdhEphemeralPublicKeyHex
  }, 'ML-KEM-768');

  // Cross-system agreement
  assert.equal(aliceDerivedSecret, bob.combinedSharedSecretHex);
});

test('Integration Reality: Multi-Round Post-Quantum Interactive Handshake', () => {
  const client = new MlKemClient();
  const sessionId = 'session-integration-pqc-001';

  // Client Hello
  const aliceKeyPair = client.createHybridKeyPair('ML-KEM-768');
  const clientHello = PqcSessionHandshake.createClientHello(sessionId, aliceKeyPair);

  // Server Hello
  const { serverHello, serverSessionKeyHex } = PqcSessionHandshake.processClientHelloAndCreateServerHello(
    client,
    clientHello
  );

  // Client Confirmation
  const { clientConfirmation, clientSessionKeyHex } = PqcSessionHandshake.processServerHelloAndConfirm(
    client,
    {
      pqcDecapsulationKeyHex: aliceKeyPair.pqcDecapsulationKeyHex,
      ecdhPrivateKeyHex: aliceKeyPair.ecdhPrivateKeyHex
    },
    serverHello,
    'ML-KEM-768'
  );

  assert.equal(clientSessionKeyHex, serverSessionKeyHex);

  // Server confirms
  const confirmed = PqcSessionHandshake.verifyClientConfirmation(serverSessionKeyHex, sessionId, clientConfirmation);
  assert.equal(confirmed, true);
});

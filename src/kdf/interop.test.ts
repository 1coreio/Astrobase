import { randomBytes } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { createInstance } from '../instance/instance.js';
import type { KeyDerivationContext } from './kdf.js';
import { NodeKDF } from './node.js';
import { WebCryptoKDF } from './web-crypto.js';

describe('KDF: Node & WebCrypto interop', () => {
  const baseOptions = {
    hashAlg: 'SHA-256',
    input: new Uint8Array(randomBytes(32)),
    instance: createInstance(),
    keyLen: 32,
    salt: new Uint8Array(randomBytes(16)),
  };

  test('HKDF', async () => {
    const options: KeyDerivationContext = {
      ...baseOptions,
      info: new Uint8Array(randomBytes(16)),
      kdf: 'HKDF',
    };

    const nodeResult = NodeKDF.HKDF(options);
    const webCryptoResult = await WebCryptoKDF.HKDF(options);

    expect(nodeResult).toEqual(webCryptoResult);
  });

  test('PBKDF', async () => {
    const options: KeyDerivationContext = {
      ...baseOptions,
      iterations: 10000,
      kdf: 'PBKDF2',
    };

    const nodeResult = NodeKDF.PBKDF2(options);
    const webCryptoResult = await WebCryptoKDF.PBKDF2(options);

    expect(nodeResult).toEqual(webCryptoResult);
  });
});

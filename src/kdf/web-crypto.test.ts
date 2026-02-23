import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { WebCryptoKDF } from './web-crypto.js';

describe('WebCrypto KDF', () => {
  it('HKDF works with undefined salt', async () => {
    const keyLen = 32;

    const result = await WebCryptoKDF.HKDF({
      hashAlg: 'SHA-256',
      info: new Uint8Array(randomBytes(8)),
      input: new Uint8Array(randomBytes(32)),
      kdf: 'HKDF',
      keyLen,
    });

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).length(keyLen);
  });
});

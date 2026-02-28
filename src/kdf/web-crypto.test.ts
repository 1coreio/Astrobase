import { randomBytes } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { WebCryptoKDF } from './web-crypto.js';

describe('WebCrypto KDF', () => {
  for (const properties of [['info'], ['salt'], ['info', 'salt']] as const) {
    test(`HKDF works with undefined ${properties.join(', ')}`, async () => {
      const keyLen = 32;

      const options: Parameters<typeof WebCryptoKDF.HKDF>[0] = {
        hashAlg: 'SHA-256',
        info: new Uint8Array(randomBytes(8)),
        input: new Uint8Array(randomBytes(32)),
        kdf: 'HKDF',
        keyLen,
        salt: new Uint8Array(randomBytes(16)),
      };

      for (const property of properties) {
        // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
        delete options[property];
      }

      const result = await WebCryptoKDF.HKDF(options);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result).length(keyLen);
    });
  }
});

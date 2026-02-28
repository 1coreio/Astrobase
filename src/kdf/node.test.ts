import { randomBytes } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { NodeKDF } from './node.js';

describe('Node KDF', () => {
  for (const properties of [['info'], ['salt'], ['info', 'salt']] as const) {
    test(`HKDF works with undefined ${properties.join(', ')}`, () => {
      const keyLen = 32;

      const options: Parameters<typeof NodeKDF.HKDF>[0] = {
        hashAlg: 'SHA-256',
        info: new Uint8Array(randomBytes(8)),
        input: new Uint8Array(randomBytes(32)),
        keyLen,
        salt: new Uint8Array(randomBytes(16)),
      };

      for (const property of properties) {
        // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
        delete options[property];
      }

      const result = NodeKDF.HKDF(options);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result).length(keyLen);
    });
  }
});

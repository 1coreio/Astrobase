import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { NodeKDF } from './node.js';

describe('Node KDF', () => {
  it('HKDF works with undefined salt', () => {
    const keyLen = 32;

    const result = NodeKDF.HKDF({
      hashAlg: 'SHA-256',
      info: new Uint8Array(randomBytes(8)),
      input: new Uint8Array(randomBytes(32)),
      keyLen,
    });

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).length(keyLen);
  });
});

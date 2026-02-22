import { randomBytes } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { createInstance } from '../instance/instance.js';
import { hmac } from './api.js';
import { HMAC_SHA256, WithHmacSha256 } from './sha256hmac.js';

describe('HMAC SHA256', () => {
  const instance = createInstance(WithHmacSha256);

  const secret1 = new Uint8Array(randomBytes(32));
  const secret2 = new Uint8Array(randomBytes(32));
  const secret3 = new Uint8Array(randomBytes(32));

  const data1 = new Uint8Array(randomBytes(16));
  const data2 = new Uint8Array(randomBytes(16));

  const compute = () =>
    Promise.all([
      hmac(instance, HMAC_SHA256, secret1, data1),
      hmac(instance, HMAC_SHA256, secret1, data2),
      hmac(instance, HMAC_SHA256, secret2, data1),
      hmac(instance, HMAC_SHA256, secret3, data2),
    ]);

  let results: Uint8Array<ArrayBuffer>[];

  beforeAll(async () => {
    results = await compute();
  });

  it('generates unique outputs', () => {
    for (const result of results) {
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
      for (const testAgainst of results) {
        if (result !== testAgainst) {
          expect(result).not.toEqual(testAgainst);
        }
      }
    }
  });

  it('is deterministic', async () => {
    expect(results).toEqual(await compute());
  });
});

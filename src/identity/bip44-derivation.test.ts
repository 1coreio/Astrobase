import { randomBytes } from 'node:crypto';
import { describe, expect, it, test } from 'vitest';
import { ContentIdentifier } from '../cid/cid.js';
import { createInstance } from '../instance/instance.js';
import { activeSeeds } from '../keyrings/keyrings.js';
import { createInstanceWithLoadedKeyring } from '../keyrings/testing/utils.js';
import { WithECDSA } from '../signatures/ecdsa.js';
import { getIdentityBIP44, getPrivateKeyBIP44, putIdentityBIP44 } from './bip44-derivation.js';

describe('Identity', () => {
  test('No keyring loaded', async () => {
    const id = 'identityNoKeyring';
    const instance = createInstance();
    const err = new ReferenceError(`No keyring loaded for instance`);
    expect(() => getPrivateKeyBIP44({ instance, publicKey: new Uint8Array() })).toThrow(err);
    await expect(getIdentityBIP44({ id, instance })).rejects.toThrow(err);
    await expect(putIdentityBIP44({ id, ref: '', instance })).rejects.toThrow(err);
  });

  describe('getPrivateKey', () => {
    const instance = createInstance();

    it('Throws if unavailable', () => {
      activeSeeds.set(instance, randomBytes(32));
      const publicKey = new Uint8Array(randomBytes(33));
      expect(() => getPrivateKeyBIP44({ instance, publicKey })).toThrow('Private key unavailable');
    });
  });

  test('putIdentity & getIdentity full test', async () => {
    const id = 'identity-test';
    const instance = await createInstanceWithLoadedKeyring(WithECDSA, {
      functions: { getPrivateKey: getPrivateKeyBIP44 },
    });

    await expect(getIdentityBIP44({ id, instance })).rejects.toThrow('Identity not found');

    let ref = new ContentIdentifier('test', Array.from(randomBytes(8)));

    const cid = await putIdentityBIP44({ id, instance, ref });
    expect(cid).toBeInstanceOf(ContentIdentifier);

    await expect(getIdentityBIP44({ id, instance })).resolves.toEqual({
      cid,
      identity: { id, ref },
      index: 0,
    });

    ref = new ContentIdentifier('test', Array.from(randomBytes(8)));

    await expect(putIdentityBIP44({ id, instance, ref })).resolves.toEqual(cid);

    await expect(getIdentityBIP44({ id, instance })).resolves.toEqual({
      cid,
      identity: { id, ref },
      index: 0,
    });
  });
});

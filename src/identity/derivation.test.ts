import { randomBytes } from 'node:crypto';
import { beforeAll, describe, expect, it, test } from 'vitest';
import { ContentIdentifier } from '../cid/cid.js';
import { createInstance, type Instance } from '../instance/instance.js';
import { createInstanceWithLoadedKeyring } from '../keyrings/testing/utils.js';
import { WithECDSA } from '../signatures/ecdsa.js';
import { getIdentity, getPrivateKey, putIdentity } from './derivation.js';

describe('Identity', () => {
  test('No keyring loaded', async () => {
    const id = 'identityNoKeyring';
    const instance = createInstance();
    const err = new ReferenceError(`No keyring loaded for instance`);
    await expect(getPrivateKey({ instance, publicKey: new Uint8Array() })).rejects.toThrow(err);
    await expect(getIdentity({ id, instance })).rejects.toThrow(err);
    await expect(putIdentity({ id, ref: '', instance })).rejects.toThrow(err);
  });

  describe('getPrivateKey', () => {
    let instance: Instance;
    let publicKey: Uint8Array<ArrayBuffer>;

    beforeAll(async () => {
      instance = await createInstanceWithLoadedKeyring();
      publicKey = new Uint8Array((await getIdentity({ id: '1234', instance })).cid.value);
    });

    it('Throws if ID unavailable in lookup', async () => {
      const result = getPrivateKey({ instance, publicKey: new Uint8Array(randomBytes(33)) });
      await expect(result).rejects.toThrow('Identity ID unavailable for public key');
    });

    it('Throws if private key unavailable in keyring', async () => {
      const instance = await createInstanceWithLoadedKeyring();
      const result = getPrivateKey({ instance, publicKey });
      await expect(result).rejects.toThrow('Private key unavailable in current keyring');
    });

    it('Successfully retrieves the private key', async () => {
      const result = await getPrivateKey({ instance, publicKey });
      expect(result).instanceOf(Uint8Array);
      expect(result).length(32);
    });
  });

  test('putIdentity & getIdentity full test', async () => {
    const id = 'identity-test';
    const instance = await createInstanceWithLoadedKeyring(WithECDSA);

    const initialIdentity = await getIdentity({ id, instance });

    expect(initialIdentity.cid).instanceOf(ContentIdentifier);
    expect(initialIdentity.identity).toBeUndefined();

    let ref = new ContentIdentifier('test', Array.from(randomBytes(8)));

    const cid = await putIdentity({ id, instance, ref });
    expect(cid).toEqual(initialIdentity.cid);

    await expect(getIdentity({ id, instance })).resolves.toEqual({
      cid,
      identity: { id, ref },
    });

    ref = new ContentIdentifier('test', Array.from(randomBytes(8)));

    await expect(putIdentity({ id, instance, ref })).resolves.toEqual(cid);

    await expect(getIdentity({ id, instance })).resolves.toEqual({
      cid,
      identity: { id, ref },
    });
  });
});

/**
 * Provides support for using the `node:crypto` API with the KDF module.
 *
 * @module KDF/Node
 * @experimental
 */

import { hkdfSync, pbkdf2Sync } from 'node:crypto';
import type { InstanceConfig } from '../instance/instance.js';
import type { KeyDerivationContext, KeyDerivationFn } from '../kdf/kdf.js';

export const NodeKDFs = ['HKDF', 'PBKDF2'] as const;

export type NodeKDF = (typeof NodeKDFs)[number];

/** A {@link KeyDerivationFn} using the `node:crypto` implementation of `PBKDF2`. */
export const NodePBKDF2 = ((options: Omit<KeyDerivationContext, 'instance' | 'kdf'>) => {
  for (const param of ['iterations', 'salt'] as const) {
    if (!options[param]) {
      throw new TypeError(`Missing '${param}' parameter for 'PBKDF2'`);
    }
  }
  if (options.info) {
    throw new TypeError(`'info' parameter not supported for 'PBKDF2'`);
  }
  return new Uint8Array(
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    pbkdf2Sync(options.input, options.salt!, options.iterations!, options.keyLen, options.hashAlg),
  );
}) satisfies KeyDerivationFn;

/** A {@link KeyDerivationFn} using the `node:crypto` implementation of `HKDF`. */
export const NodeHKDF = (({
  hashAlg,
  info,
  input,
  iterations,
  keyLen,
  salt,
}: Omit<KeyDerivationContext, 'instance' | 'kdf'>) => {
  if (!info) {
    throw new TypeError(`Missing 'info' parameter for 'HKDF'`);
  }
  if (iterations) {
    throw new TypeError(`'iterations' parameter not supported for 'HKDF'`);
  }
  return new Uint8Array(hkdfSync(hashAlg, input, salt ?? new Uint8Array(), info, keyLen));
}) satisfies KeyDerivationFn;

export const NodeKDF = {
  HKDF: NodeHKDF,
  PBKDF2: NodePBKDF2,
} satisfies Record<NodeKDF, KeyDerivationFn>;

/**
 * An {@link InstanceConfig} that provides `kdf` for algorithms supported by the the `node:crypto`
 * API.
 */
export const WithNodeKDF: InstanceConfig = { kdf: NodeKDF };

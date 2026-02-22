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
  if (!options.iterations) {
    throw new TypeError(`Missing 'iterations' parameter for 'PBKDF2'`);
  }
  if (options.info) {
    throw new TypeError(`'info' parameter not supported for 'PBKDF2'`);
  }
  return new Uint8Array(
    pbkdf2Sync(options.input, options.salt, options.iterations, options.keyLen, options.hashAlg),
  );
}) satisfies KeyDerivationFn;

/** A {@link KeyDerivationFn} using the `node:crypto` implementation of `HKDF`. */
export const NodeHKDF = ((options: Omit<KeyDerivationContext, 'instance' | 'kdf'>) => {
  if (!options.info) {
    throw new TypeError(`Missing 'info' parameter for 'HKDF'`);
  }
  if (options.iterations) {
    throw new TypeError(`'iterations' parameter not supported for 'HKDF'`);
  }
  return new Uint8Array(
    hkdfSync(options.hashAlg, options.input, options.salt, options.info, options.keyLen),
  );
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

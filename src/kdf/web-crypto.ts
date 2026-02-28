/**
 * Provides support for using the WebCrypto API with the KDF module.
 *
 * @module KDF/WebCrypto
 * @experimental
 */

import type { InstanceConfig } from '../instance/instance.js';
import type { KeyDerivationContext, KeyDerivationFn } from '../kdf/kdf.js';

export const WebCryptoKDFs = ['HKDF', 'PBKDF2'] as const;

export type WebCryptoKDF = (typeof WebCryptoKDFs)[number];

/** A {@link KeyDerivationFn} using the WebCrypto API for supported algorithms. */
export const WebCryptoKdfFn = (async ({
  input,
  kdf,
  keyLen,
  ...options
}: Omit<KeyDerivationContext, 'instance'>) => {
  if (!WebCryptoKDFs.includes(kdf as never)) {
    throw new Error(`Unsupported KDF '${kdf}'`);
  }

  if (kdf === 'PBKDF') {
    for (const param of ['iterations', 'salt'] as const) {
      if (!options[param]) {
        throw new TypeError(`Missing '${param}' parameter for ${kdf}`);
      }
    }
  }

  const mustOmit = kdf === 'HKDF' ? 'iterations' : 'info';
  if (options[mustOmit]) {
    throw new TypeError(`'${mustOmit}' parameter not supported for ${kdf}`);
  }

  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: kdf,
        hash: options.hashAlg,
        info: options.info ?? new Uint8Array(),
        iterations: options.iterations,
        salt: options.salt ?? new Uint8Array(),
      },
      await crypto.subtle.importKey('raw', input, kdf, false, ['deriveBits']),
      keyLen * 8,
    ),
  );
}) satisfies KeyDerivationFn;

export const WebCryptoKDF = {
  PBKDF2: WebCryptoKdfFn,
  HKDF: WebCryptoKdfFn,
} satisfies Record<WebCryptoKDF, KeyDerivationFn>;

export const WithWebCryptoKDF = { kdf: WebCryptoKDF } satisfies InstanceConfig;

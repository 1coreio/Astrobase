import type { InstanceConfig } from '../instance/instance.js';
import type { HmacFn } from './api.js';

/** The identifier for SHA-256 HMAC. */
export const HMAC_SHA256 = 'hmac-sha256';

/** A {@link HmacFn} that computes SHA-256 HMAC using the WebCrypto API. */
export const hmacSha256 = (async (secret, data) => {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data));
}) satisfies HmacFn;

/** An {@link InstanceConfig} that provides SHA-256 HMAC using the WebCrypto API. */
export const WithHmacSha256 = { hmac: { [HMAC_SHA256]: hmacSha256 } } satisfies InstanceConfig;

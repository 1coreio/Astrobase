import { getOrThrow, type Instance } from '../instance/instance.js';
import type { MaybePromise } from '../internal/maybe-promise.js';

/**
 * A HMAC function implementation.
 *
 * @param secret The secret.
 * @param data The message.
 * @returns A promise that resolves with the HMAC signature bytes.
 */
export type HmacFn = (
  secret: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
) => MaybePromise<Uint8Array<ArrayBuffer>>;

/**
 * Performs the hashing algorithm on the given buffer.
 *
 * @param instance The instance for algorithm resolution.
 * @param alg The the type of the hashing algorithm to use.
 * @param secret The secret bytes.
 * @param data The HMAC data bytes.
 * @returns A promise that resolves with the HMAC signature bytes.
 */
export const hmac = async (
  instance: Instance,
  alg: string,
  secret: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
) => getOrThrow(instance, 'hmac', alg)(secret, data);

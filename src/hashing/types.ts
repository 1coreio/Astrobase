import type { Hash } from './hash.js';

/**
 * A valid hash value that includes the algorithm identifier prefix. This can be one of:
 *
 * - An `ArrayLike` of byte values.
 * - An `ArrayBufferLike`.
 * - A {@link Hash} instance.
 */
export type HashLike = ArrayLike<number> | ArrayBuffer | Hash;

/**
 * A hash function implementation.
 *
 * @param data The data to compute hash from.
 * @returns A promise that resolves with the computed hash bytes.
 */
export type HashFn = (data: BufferSource) => Promise<ArrayBuffer>;

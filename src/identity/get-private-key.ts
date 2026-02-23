/* eslint-disable @typescript-eslint/no-deprecated */

import type { MaybePromise } from '../internal/maybe-promise.js';
import { getPrivateKey, type GetPrivateKeyOptions } from './derivation.js';

export type GetPrivateKeyFn = (
  options: GetPrivateKeyOptions,
) => MaybePromise<Uint8Array<ArrayBuffer>>;

export const getPrivateKeyViaInstance = ((options) =>
  (options.instance.functions.getPrivateKey ?? getPrivateKey)(options)) satisfies GetPrivateKeyFn;

// prettier-ignore
import { instance, maxLength, nonEmpty, pipe, regex, safeParse, strictObject, string } from 'valibot';
import { ContentIdentifier, type ContentIdentifierSchemeParser } from '../cid/cid.js';
import { compareBytes } from '../internal/encoding.js';
import type { UnwrappedSignature } from '../signatures/wrap.js';
import { unwrap } from '../wraps/wraps.js';

/** Parsed identity content. */
export interface Identity {
  /**
   * A string ID used to find an identity when iterating through addresses with non-deterministic
   * identity derivation.
   *
   * @deprecated
   */
  id?: string;

  /** The content this identity points to. */
  ref: ContentIdentifier;
}

/** The content identifier prefix for identity. */
export const prefix = '$pub';

/** The Valibot schema for identity content. */
export const schema = strictObject({
  /** @ignore */
  id: pipe(string(), nonEmpty(), maxLength(100), regex(/^[a-z0-9-]+$/)),
  /** @ignore */
  ref: instance(ContentIdentifier),
});

/** The identity {@link ContentIdentifierSchemeParser}. */
export const scheme: ContentIdentifierSchemeParser<Identity> = async (cid, content, instance) => {
  const { metadata, type, value } = await unwrap(instance, content);
  if (type !== 'sig') return;
  const unwrappedSig = (await metadata.getValue(instance)) as UnwrappedSignature[];
  if (
    Array.isArray(unwrappedSig) &&
    unwrappedSig.some(({ publicKey }) => compareBytes(publicKey, new Uint8Array(cid.value)))
  ) {
    const parse = safeParse(schema, await value.getValue(instance));
    return parse.success ? parse.output : undefined;
  }
};

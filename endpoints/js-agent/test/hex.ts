// Shared hex / UTF-8 helpers for the crypto golden-vector tests. Test vectors
// are universally expressed in hex, and the KDF inputs as UTF-8 strings.

export const toHex = (u: Uint8Array): string =>
  Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");

export const fromHex = (s: string): Uint8Array => {
  // Strict: these tests exist to catch a drifted golden vector, so a malformed
  // hex constant (odd length / non-hex char) must fail loudly here rather than
  // silently decode to the wrong bytes and surface as a confusing mismatch.
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error(`invalid hex string: ${JSON.stringify(s)}`);
  }
  const pairs = s.match(/../g);
  return pairs
    ? Uint8Array.from(pairs, (h) => parseInt(h, 16))
    : new Uint8Array(0);
};

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

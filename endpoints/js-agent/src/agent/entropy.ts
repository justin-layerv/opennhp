/**
 * Fills `out` with cryptographically-strong random bytes, in place — the
 * injectable random-bytes seam (the browser CSPRNG in production, a deterministic
 * fake in tests). `out` is `Uint8Array<ArrayBuffer>` (not a `SharedArrayBuffer`
 * view) because the production `crypto.getRandomValues` rejects shared buffers;
 * callers allocate a fresh `new Uint8Array(n)`, which already satisfies that bound.
 */
export type RandomBytes = (out: Uint8Array<ArrayBuffer>) => void;

import type { KnockEntropy } from "../src/agent/knock";

/**
 * Entropy that hands out the queued byte chunks in order, then a fixed clock.
 * The order is load-bearing: `createKnock` consumes the chunks as
 * [ephemeral (32 B), counter (8 B), preamble (4 B)] — if that read order changes
 * in `createKnock`, every caller's queued chunks must move with it.
 */
export function fixedEntropy(
  chunks: Uint8Array[],
  nowNanos: bigint,
): KnockEntropy {
  let i = 0;
  return {
    randomBytes: (out) => {
      out.set(chunks[i++] ?? new Uint8Array(out.length));
    },
    nowNanos: () => nowNanos,
  };
}

/** The 8-byte big-endian encoding of a uint64 — the counter chunk for
 * {@link fixedEntropy}. */
export function u64be(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

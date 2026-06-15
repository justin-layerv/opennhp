import { describe, it, expect } from "vitest";
import {
  pubKeyFingerprint,
  PUBKEY_FINGERPRINT_LEN,
} from "../src/crypto/fingerprint";

describe("pubKeyFingerprint", () => {
  // CROSS-LANGUAGE GOLDEN VECTORS — identical to the Go test in
  // nhp/utils/crypto_fingerprint_test.go. They pin the POST /relay/{serverId}
  // routing contract: the browser and the Go relay must derive the same id, or
  // the browser would address the wrong (or no) cell server.
  //
  // Each side still asserts its OWN implementation against its own copy of these
  // constants, in its own toolchain (this vitest job is path-scoped and never
  // runs Go). The two copies no longer drift silently: the marked lines below
  // are extracted and compared against the Go test by
  // scripts/check-golden-vectors.sh (wired into CI), so a one-sided
  // algorithm change (hash, prefix length, or base64 variant) fails the build.
  // Keep each nhp-golden-vector label matched with the Go test's label.
  const WANT_FILL_0X42 = "Ql7U5KNrMOo"; // nhp-golden-vector: fill-0x42
  const WANT_SEQ_1_TO_32 = "riFsLvUkejc"; // nhp-golden-vector: seq-1to32

  it("matches the Go golden vector for a 32-byte key filled with 0x42", () => {
    const filled = new Uint8Array(32).fill(0x42);
    expect(pubKeyFingerprint(filled)).toBe(WANT_FILL_0X42);
  });

  it("matches the Go golden vector for bytes [1..32]", () => {
    const seq = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seq[i] = i + 1;
    expect(pubKeyFingerprint(seq)).toBe(WANT_SEQ_1_TO_32);
  });

  it("maps distinct keys to distinct fingerprints (no serverId collision)", () => {
    // Mirrors Go TestPubKeyFingerprintDistinct (same inputs): two different cell
    // servers must not collide to the same POST /relay/{serverId} routing id —
    // the property that actually matters operationally.
    const a = new TextEncoder().encode("key-a-key-a-key-a-key-a-key-a-32");
    const b = new TextEncoder().encode("key-b-key-b-key-b-key-b-key-b-32");
    expect(pubKeyFingerprint(a)).not.toBe(pubKeyFingerprint(b));
  });

  it("is deterministic and PUBKEY_FINGERPRINT_LEN chars", () => {
    const key = new TextEncoder().encode(
      "deterministic-input-not-a-golden-vector",
    );
    const first = pubKeyFingerprint(key);
    expect(pubKeyFingerprint(key)).toBe(first);
    expect(first.length).toBe(PUBKEY_FINGERPRINT_LEN);
  });

  it("positively verifies the base64url +→- and /→_ substitution", () => {
    // A 0x70-filled key is chosen deliberately: its 8-byte SHA-256 prefix is
    // "p8u/3+Ocffc" in STANDARD base64 — it contains BOTH + and /, so
    // RawURLEncoding must substitute both. Pinning the exact URL-safe output
    // (which contains both - and _) positively verifies the mapping: a bug that
    // *deleted* +/ instead of substituting would yield a shorter wrong string
    // and fail here, not just a bug that left them in. The value is the canonical
    // algorithm's output — the same oracle reproduces the two golden vectors
    // above — so this also pins TS↔Go parity on the substitution path.
    const fp = pubKeyFingerprint(new Uint8Array(32).fill(0x70));
    expect(fp).toBe("p8u_3-Ocffc");
    expect(fp).not.toMatch(/[+/=]/); // never standard-base64 chars or = padding
    expect(fp.length).toBe(PUBKEY_FINGERPRINT_LEN);
  });
});

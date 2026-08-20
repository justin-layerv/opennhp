import { describe, expect, it } from "vitest";
import { base64UrlEncode } from "../src/qurl/base64url";
import {
  decodeQurlV2Transport,
  QURL_V2_TRANSPORT_CHUNK_CHARS,
  QURL_V2_TRANSPORT_MAX_CHARS,
  QurlV2TransportError,
} from "../src/qurl/transport";
import { wrapQurlV2TransportFixture } from "./qurl-transport-fixture";

const SIMPLE_CANONICAL = "qv2.A.B.C";
const SIMPLE_TRANSPORT = "qv2t1.1.1.1.A.B.C";

describe("decodeQurlV2Transport", () => {
  it("restores the exact canonical qv2 bytes from one or many chunks", () => {
    expect(decodeQurlV2Transport(SIMPLE_TRANSPORT)).toBe(SIMPLE_CANONICAL);

    const claims = "A".repeat(QURL_V2_TRANSPORT_CHUNK_CHARS * 2 + 16);
    const secret = "B".repeat(QURL_V2_TRANSPORT_CHUNK_CHARS + 16);
    const signature = "C".repeat(88);
    const canonical = `qv2.${claims}.${secret}.${signature}`;
    expect(decodeQurlV2Transport(wrapQurlV2TransportFixture(canonical))).toBe(
      canonical,
    );
  });

  it("reconstructs alphabet-valid inner data for the strict parser to judge", () => {
    // These are deliberately not canonical base64url fields. Transport framing
    // accepts and preserves them; parseFragment/knockQurlV2 rejects downstream.
    expect(decodeQurlV2Transport("qv2t1.1.1.1.A.B.C")).toBe("qv2.A.B.C");
    expect(decodeQurlV2Transport("qv2t1.1.1.1.AA.AA.A")).toBe("qv2.AA.AA.A");
  });

  it("preserves reordered equal-width chunks exactly", () => {
    const a = "A".repeat(240);
    const b = "B".repeat(240);
    expect(decodeQurlV2Transport(`qv2t1.2.1.1.${a}.${b}.C.D`)).toBe(
      `qv2.${a}${b}.C.D`,
    );
    expect(decodeQurlV2Transport(`qv2t1.2.1.1.${b}.${a}.C.D`)).toBe(
      `qv2.${b}${a}.C.D`,
    );
  });

  it("accepts every canonical field at its encoded-part cap", () => {
    const canonical = `qv2.${"A".repeat(6 * 1024)}.${"B".repeat(512)}.${"C".repeat(128)}`;
    const transport = wrapQurlV2TransportFixture(canonical);
    expect(transport).toHaveLength(QURL_V2_TRANSPORT_MAX_CHARS);
    expect(decodeQurlV2Transport(transport)).toBe(canonical);
  });

  it.each([
    ["leading hash at body boundary", `#${SIMPLE_TRANSPORT}`],
    ["legacy qv2", "qv2.AA.AA.AA"],
    ["unknown transport version", "qv2t2.1.1.1.AA.AA.AA"],
    ["full URL", `https://qurl.link/#${SIMPLE_TRANSPORT}`],
  ])("rejects %s public transport", (_name, transport) => {
    expect(() => decodeQurlV2Transport(transport)).toThrow(
      QurlV2TransportError,
    );
  });

  it.each(["0", "00", "01", "+1", "-1", "1e0", " 1", "1 "])(
    "rejects non-canonical claims count %j",
    (count) => {
      expect(() =>
        decodeQurlV2Transport(`qv2t1.${count}.1.1.AA.AA.AA`),
      ).toThrow(/claims chunk count must be canonical positive decimal/);
    },
  );

  it.each([
    ["claims", "27", "1", "1"],
    ["secret", "1", "4", "1"],
    ["signature", "1", "1", "2"],
  ])("rejects a %s count above its cap", (_name, claims, secret, sig) => {
    expect(() =>
      decodeQurlV2Transport(`qv2t1.${claims}.${secret}.${sig}.AA.AA.AA`),
    ).toThrow(QurlV2TransportError);
  });

  it.each([
    ["missing chunk", "qv2t1.1.1.1.AA.AA"],
    ["extra chunk", "qv2t1.1.1.1.AA.AA.AA.AA"],
    ["empty chunk", "qv2t1.1.1.1.AA..AA"],
  ])("rejects an inexact layout: %s", (_name, transport) => {
    expect(() => decodeQurlV2Transport(transport)).toThrow(
      QurlV2TransportError,
    );
  });

  it("enforces the canonical 240-character chunk width", () => {
    expect(() =>
      decodeQurlV2Transport(`qv2t1.2.1.1.${"A".repeat(239)}.AA.AA.AA`),
    ).toThrow(/claims non-final chunk must be exactly 240 characters/);
    expect(() =>
      decodeQurlV2Transport(`qv2t1.1.1.1.${"A".repeat(241)}.AA.AA`),
    ).toThrow(/claims chunk exceeds 240 characters/);
  });

  it.each([
    ["padding", "AA="],
    ["standard-base64 alphabet", "AA+"],
    ["separator inside data", "AA.AA"],
  ])("rejects a chunk with %s", (_name, chunk) => {
    expect(() => decodeQurlV2Transport(`qv2t1.1.1.1.${chunk}.AA.AA`)).toThrow();
  });

  it.each([
    ["claims", "26", "1", "1", 25, 145, 2, 2],
    ["secret", "1", "3", "1", 0, 2, 33, 2],
    ["signature", "1", "1", "1", 0, 2, 2, 129],
  ])(
    "rejects the %s part above its canonical cap",
    (
      _name,
      claimsCount,
      secretCount,
      sigCount,
      fullClaims,
      claimsLast,
      secretLast,
      sigLast,
    ) => {
      const chunks = [
        ...Array.from({ length: fullClaims }, () => "A".repeat(240)),
        "A".repeat(claimsLast),
      ];
      if (Number(secretCount) > 1) {
        chunks.push(
          ...Array.from({ length: Number(secretCount) - 1 }, () =>
            "B".repeat(240),
          ),
        );
      }
      chunks.push("A".repeat(secretLast), "A".repeat(sigLast));
      expect(() =>
        decodeQurlV2Transport(
          ["qv2t1", claimsCount, secretCount, sigCount, ...chunks].join("."),
        ),
      ).toThrow(QurlV2TransportError);
    },
  );

  it("rejects an oversized fragment before calling split", () => {
    const stringPrototype = String.prototype as unknown as {
      split: (...args: unknown[]) => string[];
    };
    const originalSplit = stringPrototype.split;
    let splitCalled = false;
    let thrown: unknown;
    stringPrototype.split = function (...args: unknown[]) {
      splitCalled = true;
      return Reflect.apply(originalSplit, this, args) as string[];
    };
    try {
      decodeQurlV2Transport("A".repeat(QURL_V2_TRANSPORT_MAX_CHARS + 1));
    } catch (error) {
      thrown = error;
    } finally {
      stringPrototype.split = originalSplit;
    }
    expect(thrown).toBeInstanceOf(QurlV2TransportError);
    expect(splitCalled).toBe(false);
  });

  it("round-trips a deterministic spread of valid field lengths", () => {
    let state = 0x6d2b79f5;
    const nextByte = (): number => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state & 0xff;
    };
    const field = (maxBytes: number): string => {
      const length = 1 + (nextByte() % maxBytes);
      return base64UrlEncode(Uint8Array.from({ length }, () => nextByte()));
    };

    for (let i = 0; i < 200; i += 1) {
      const canonical = `qv2.${field(4608)}.${field(384)}.${field(96)}`;
      const transport = wrapQurlV2TransportFixture(canonical);
      expect(decodeQurlV2Transport(transport)).toBe(canonical);
    }
  });
});

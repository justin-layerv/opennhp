import { describe, it, expect } from "vitest";
import { HashType } from "../src/crypto/hash";
import { keyGen1, keyGen2, keyGen3, mixKey } from "../src/crypto/kdf";
import { toHex, utf8 } from "./hex";

// CROSS-LANGUAGE GOLDEN VECTORS — identical to the Go test in
// nhp/core/kdf_test.go (key/input strings and the BLAKE2s + SHA256 expected
// digests are copied verbatim). The KDF is the most custom piece of the wire
// crypto — HMAC over the *unkeyed* hash with 0x01/0x02/0x03 domain tags — and a
// mismatch here means the browser would derive different handshake keys than
// the Go server and every knock would fail to decrypt.
//
// Each side asserts its own implementation against its own copy (this vitest
// job never runs Go). The two copies no longer drift silently: the marked dst
// lines below are extracted and compared against the Go test by
// scripts/check-golden-vectors.sh (wired into CI), so a one-sided change fails
// the build (#2556). Keep each nhp-golden-vector label matched with the Go test.
const KEY = utf8("KDF test key for vector coverage");
const INPUT = utf8("KDF test input for vector coverage");

interface Vector {
  name: string;
  type: HashType;
  dst0: string;
  dst1: string;
  dst2: string;
}

const VECTORS: Vector[] = [
  {
    name: "BLAKE2s",
    type: HashType.BLAKE2S,
    dst0: "5603731d8149d45d1100909addb244063ab505e04288c9f2632fb0e167af0b95", // nhp-golden-vector: kdf-blake2s-dst0
    dst1: "75c6a3037c6ac51ac536f94ce239b275d5d098092d6776b905cde91491d16807", // nhp-golden-vector: kdf-blake2s-dst1
    dst2: "83c6cf425a88b426e3e92b1e9cd14ddb31066aeeb2071597a8106a36a4055a7d", // nhp-golden-vector: kdf-blake2s-dst2
  },
  {
    name: "SHA256",
    type: HashType.SHA256,
    dst0: "f296bc34384ca0d49ab2bede40c5ddb126aca8ec5da639b8f631d4dc3ed42ac7", // nhp-golden-vector: kdf-sha256-dst0
    dst1: "243c77a97d9402ffc50215ced8572d2784d61929bacedbbedceda91410564ab6", // nhp-golden-vector: kdf-sha256-dst1
    dst2: "14dec35f867351badeb4bdd7ca7be63bd84338571d74e05f586872e28f3374a3", // nhp-golden-vector: kdf-sha256-dst2
  },
];

describe("NHP KDF (NoiseFactory) — golden vectors vs nhp/core/kdf_test.go", () => {
  for (const v of VECTORS) {
    it(`${v.name}: KeyGen1 and MixKey both yield dst0`, () => {
      expect(toHex(keyGen1(v.type, KEY, INPUT))).toBe(v.dst0);
      // MixKey is an alias of KeyGen1 — assert the contract, not just the impl.
      expect(toHex(mixKey(v.type, KEY, INPUT))).toBe(v.dst0);
    });

    it(`${v.name}: KeyGen2 yields dst0, dst1`, () => {
      const [d0, d1] = keyGen2(v.type, KEY, INPUT);
      expect(toHex(d0)).toBe(v.dst0);
      expect(toHex(d1)).toBe(v.dst1);
    });

    it(`${v.name}: KeyGen3 yields dst0, dst1, dst2`, () => {
      const [d0, d1, d2] = keyGen3(v.type, KEY, INPUT);
      expect(toHex(d0)).toBe(v.dst0);
      expect(toHex(d1)).toBe(v.dst1);
      expect(toHex(d2)).toBe(v.dst2);
    });
  }
});

import { QURL_V2_TRANSPORT_CHUNK_CHARS } from "../src/qurl/transport";

/** Test-only encoder for canonical `qv2.<claims>.<secret>.<sig>` fixtures. */
export function wrapQurlV2TransportFixture(canonicalFragment: string): string {
  const body = canonicalFragment.startsWith("#")
    ? canonicalFragment.slice(1)
    : canonicalFragment;
  const parts = body.split(".");
  if (parts.length !== 4 || parts[0] !== "qv2") {
    throw new Error("test fixture must be a canonical qv2 fragment");
  }

  const groups = parts.slice(1).map((field) => {
    const chunks: string[] = [];
    for (
      let offset = 0;
      offset < field.length;
      offset += QURL_V2_TRANSPORT_CHUNK_CHARS
    ) {
      chunks.push(field.slice(offset, offset + QURL_V2_TRANSPORT_CHUNK_CHARS));
    }
    if (chunks.length === 0) {
      throw new Error("test fixture fields must not be empty");
    }
    return chunks;
  });

  return [
    "qv2t1",
    String(groups[0]!.length),
    String(groups[1]!.length),
    String(groups[2]!.length),
    ...groups[0]!,
    ...groups[1]!,
    ...groups[2]!,
  ].join(".");
}

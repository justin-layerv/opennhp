import { describe, it, expect } from "vitest";
import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildProductionBundle,
  BUNDLE_BUDGET_GZIP_BYTES,
  OUTFILE_PATH,
  sriFor,
} from "../scripts/bundle.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const QURL_LINK_BUNDLE_PATH = resolve(
  __dirname,
  "../../../terraform/modules/qurl-link/frontend/nhp-agent.min.js",
);
const QURL_LINK_BUNDLE_SRI_PATH = `${QURL_LINK_BUNDLE_PATH}.sri`;

// Verifies the production bundle (the exact `npm run bundle` config) without
// executing it: the bundle targets the browser (document/window/fetch), and
// node-vitest has no DOM — so we assert the artifact's size and export surface
// from esbuild's metafile rather than importing it. (End-to-end exercise of the
// real browser glue is the deferred DOM-env seam, #2616.)
describe("production bundle", () => {
  it("bundles to one self-contained ESM file under the gzip budget, exposing the public API", async () => {
    const { result, gzip } = await buildProductionBundle({
      write: false, // in-memory; don't touch dist/
      metafile: true,
    });

    expect(result.errors).toEqual([]);
    expect(result.outputFiles).toHaveLength(1); // one output file

    expect(gzip).toBeLessThanOrEqual(BUNDLE_BUDGET_GZIP_BYTES);

    const output = Object.values(result.metafile!.outputs)[0]!;

    // Truly self-contained — nothing left external. A stray `external:` in the
    // options would still emit one file (and a *smaller* gzip, so the budget gate
    // alone wouldn't catch it), just with residual import statements.
    expect(output.imports).toEqual([]);

    // Export names come from the metafile (no execution). Type-only exports
    // (KnockRequest/KnockResult/KnockSuccess, the Renewal* types, the qURL v2
    // Fragment/Claims/Secret/EcPublicJwk/QurlV2Knock* types) are erased, so this is
    // the complete runtime public surface. Adding a new public export is *expected*
    // to fail this assertion — that's the surface-change tripwire; the fix is to add
    // the name to the list below. The qURL v2 entries are the construct/call/catch
    // surface the qurl.link page needs: knockQurlV2 (call), TrustStore +
    // RelayAllowlist (construct), and the error classes it branches on
    // (QurlV2TransportError, FragmentError, SignatureError, RelayUrlError,
    // UnknownKidError, plus the
    // parse-level StrictParseError/KeyLengthError/Base64UrlError that knockQurlV2
    // can surface from a malformed fragment).
    expect([...output.exports].sort()).toEqual([
      "Base64UrlError",
      "FragmentError",
      "KeyLengthError",
      "PUBKEY_FINGERPRINT_LEN",
      "QurlV2TransportError",
      "RelayAllowlist",
      "RelayError",
      "RelayUrlError",
      "SignatureError",
      "StrictParseError",
      "TrustStore",
      "UnknownKidError",
      "generateDeviceKeyPair",
      "knock",
      "knockQurlV2",
      "pubKeyFingerprint",
      "startRenewal",
      "x25519KeyFromBase64",
      "x25519KeyToBase64",
    ]);
  });

  it("selects the JS output when esbuild emits sidecar files", async () => {
    const { result, bytes } = await buildProductionBundle({
      write: false,
      sourcemap: true,
    });

    const jsOutput = result.outputFiles?.find(
      (output) => output.path === OUTFILE_PATH,
    );
    expect(jsOutput).toBeDefined();
    expect(
      result.outputFiles?.some((output) => output.path.endsWith(".js.map")),
    ).toBe(true);
    expect(bytes.equals(Buffer.from(jsOutput!.contents))).toBe(true);
  });

  it("matches the qurl-link static bundle served by Terraform", async () => {
    const { result, bytes: generated } = await buildProductionBundle({
      write: false,
    });

    expect(result.errors).toEqual([]);
    expect(result.outputFiles).toHaveLength(1);

    const deployed = await readFile(QURL_LINK_BUNDLE_PATH);
    expect(deployed.equals(generated)).toBe(true);

    const deployedSRI = (
      await readFile(QURL_LINK_BUNDLE_SRI_PATH, "utf8")
    ).trim();
    expect(deployedSRI).toBe(sriFor(generated));
  });
});

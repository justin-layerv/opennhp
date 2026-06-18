import { describe, it, expect } from "vitest";
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { bundleOptions, BUNDLE_BUDGET_GZIP_BYTES } from "../scripts/bundle.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const QURL_LINK_BUNDLE_PATH = resolve(
  __dirname,
  "../../../terraform/modules/qurl-link/frontend/nhp-agent.min.js",
);

// Verifies the production bundle (the exact `npm run bundle` config) without
// executing it: the bundle targets the browser (document/window/fetch), and
// node-vitest has no DOM — so we assert the artifact's size and export surface
// from esbuild's metafile rather than importing it. (End-to-end exercise of the
// real browser glue is the deferred DOM-env seam, #2616.)
describe("production bundle", () => {
  it("bundles to one self-contained ESM file under the gzip budget, exposing the public API", async () => {
    const result = await build({
      ...bundleOptions,
      write: false, // in-memory; don't touch dist/
      metafile: true,
    });

    expect(result.errors).toEqual([]);
    expect(result.outputFiles).toHaveLength(1); // one output file

    // outputFiles / metafile are present given write:false + metafile:true.
    const gzip = gzipSync(Buffer.from(result.outputFiles![0]!.contents), {
      level: 9,
    }).length;
    expect(gzip).toBeLessThanOrEqual(BUNDLE_BUDGET_GZIP_BYTES);

    const output = Object.values(result.metafile!.outputs)[0]!;

    // Truly self-contained — nothing left external. A stray `external:` in the
    // options would still emit one file (and a *smaller* gzip, so the budget gate
    // alone wouldn't catch it), just with residual import statements.
    expect(output.imports).toEqual([]);

    // Export names come from the metafile (no execution). Type-only exports
    // (KnockRequest/KnockResult/KnockSuccess, the Renewal* types) are erased, so
    // this is the complete runtime public surface PR-6 ships. Adding a new public
    // export is *expected* to fail this assertion — that's the surface-change
    // tripwire; the fix is to add the name to the list below.
    expect([...output.exports].sort()).toEqual([
      "PUBKEY_FINGERPRINT_LEN",
      "RelayError",
      "knock",
      "pubKeyFingerprint",
      "startRenewal",
    ]);
  });

  it("matches the qurl-link static bundle served by Terraform", async () => {
    const result = await build({
      ...bundleOptions,
      write: false,
    });

    expect(result.errors).toEqual([]);
    expect(result.outputFiles).toHaveLength(1);

    const generated = Buffer.from(result.outputFiles![0]!.contents);
    const deployed = await readFile(QURL_LINK_BUNDLE_PATH);
    expect(deployed.equals(generated)).toBe(true);
  });
});

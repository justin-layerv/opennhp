// @ts-check
// Production bundle for the browser NHP agent (#2208, PR-6 of the js-agent
// sequence). Produces one self-contained ESM file — the @noble suite (X25519 /
// AES-256-GCM / BLAKE2s+SHA-256) inlined alongside the agent loop + scheduler —
// that the qurl.link page loads as a same-origin `<script type="module" src>`.
//
// This is the Phase-1 packaging deliverable of #2208; it is *consumed* by the
// Phase-2 page migration (Phase-2 #6). The qurl-link Terraform module
// hash-pins its inline verifier scripts, renders this bundle with
// `integrity="sha384-..."`, and adds `script-src 'self'` plus relay-only
// `connect-src` while this bundle is enabled.
//
// `bundle.test.ts` imports the same options so the test verifies the exact
// production build (in-memory, via esbuild's metafile — no execution, since the
// browser-targeted bundle has no DOM in node; that seam is #2616). `// @ts-check`
// keeps this script self-checking, so the test's typed import can't drift from it.
import { build } from "esbuild";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
export const JS_AGENT_ROOT = resolve(SCRIPT_DIR, "..");
export const OUTFILE = "dist/nhp-agent.min.js";
export const OUTFILE_PATH = resolve(JS_AGENT_ROOT, OUTFILE);

/**
 * Shared esbuild options. `target: es2020` matches tsconfig and the broad browser
 * support the agent needs (Chrome / Safari / Firefox / mobile webviews);
 * `platform: browser` selects @noble's browser conditions.
 * @type {import("esbuild").BuildOptions}
 */
export const bundleOptions = {
  absWorkingDir: JS_AGENT_ROOT,
  entryPoints: [resolve(JS_AGENT_ROOT, "src/index.ts")],
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2020",
  platform: "browser",
  outfile: OUTFILE_PATH,
};

/** Gzipped-size ceiling. Currently ~23 KB (the @noble suite dominates); the
 * headroom trips a real regression — a duplicate dependency, an errant Node
 * polyfill pulled into the browser bundle — without false alarms on @noble patch
 * bumps. Gzipped is the over-the-wire metric that matters for page load. The
 * build log prints the exact size. */
export const BUNDLE_BUDGET_GZIP_BYTES = 30_000;

/**
 * @param {import("esbuild").BuildResult} result
 */
function bundleJSOutput(result) {
  const jsOutputs = (result.outputFiles ?? []).filter((output) =>
    output.path.endsWith(".js"),
  );
  if (jsOutputs.length !== 1) {
    throw new Error(`bundle build produced ${jsOutputs.length} JS outputs`);
  }
  const jsOutput = jsOutputs[0];
  if (jsOutput == null) {
    throw new Error("bundle build produced no JS output");
  }
  return jsOutput;
}

/**
 * Build the production browser bundle and enforce its gzip budget.
 * @param {import("esbuild").BuildOptions} [overrides]
 */
export async function buildProductionBundle(overrides = {}) {
  const options = { ...bundleOptions, ...overrides };
  const result = await build(options);
  const bytes =
    options.write === false
      ? Buffer.from(bundleJSOutput(result).contents)
      : await readFile(OUTFILE_PATH);
  if (bytes.length === 0) {
    throw new Error("bundle build produced no output bytes");
  }
  const gzip = gzipSync(bytes, { level: 9 }).length;
  const kb = (/** @type {number} */ n) => (n / 1024).toFixed(1);
  console.log(
    `bundle ${OUTFILE}: min=${kb(bytes.length)}KB ` +
      `gzip=${kb(gzip)}KB (budget ${kb(BUNDLE_BUDGET_GZIP_BYTES)}KB gzip)`,
  );
  if (gzip > BUNDLE_BUDGET_GZIP_BYTES) {
    throw new Error(
      `bundle exceeds gzip budget: ${gzip} > ${BUNDLE_BUDGET_GZIP_BYTES} bytes`,
    );
  }
  return { result, bytes, gzip };
}

/**
 * Subresource Integrity value (`sha384-<base64>`) for a bundle's bytes - the
 * single source of truth shared by the sync script (which writes the `.sri`
 * sidecar) and the parity test (which checks it against a fresh build).
 * @param {Buffer} bytes
 */
export function sriFor(bytes) {
  return "sha384-" + createHash("sha384").update(bytes).digest("base64");
}

async function main() {
  await buildProductionBundle();
}

// Build only when invoked directly (`npm run bundle`); a no-op when imported by
// the test, which drives esbuild itself in-memory.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

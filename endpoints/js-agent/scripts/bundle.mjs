// @ts-check
// Production bundle for the browser NHP agent (#2208, PR-6 of the js-agent
// sequence). Produces one self-contained ESM file — the @noble suite (X25519 /
// AES-256-GCM / BLAKE2s+SHA-256) inlined alongside the agent loop + scheduler —
// that the qurl.link page loads as a same-origin `<script type="module" src>`.
//
// This is the Phase-1 packaging deliverable of #2208; it is *consumed* by the
// Phase-2 page migration (Phase-2 #6), not wired here. Note for Phase-2: the
// qurl-link CloudFront CSP is `script-src 'unsafe-inline'` today (no `'self'`),
// so loading this external module needs `'self'` added to `script-src` in
// terraform/modules/qurl-link/main.tf — a deliberately separate change.
//
// `bundle.test.ts` imports the same options so the test verifies the exact
// production build (in-memory, via esbuild's metafile — no execution, since the
// browser-targeted bundle has no DOM in node; that seam is #2616). `// @ts-check`
// keeps this script self-checking, so the test's typed import can't drift from it.
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const OUTFILE = "dist/nhp-agent.min.js";

/**
 * Shared esbuild options. `target: es2020` matches tsconfig and the broad browser
 * support the agent needs (Chrome / Safari / Firefox / mobile webviews);
 * `platform: browser` selects @noble's browser conditions.
 * @type {import("esbuild").BuildOptions}
 */
export const bundleOptions = {
  entryPoints: ["src/index.ts"],
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2020",
  platform: "browser",
  outfile: OUTFILE,
};

/** Gzipped-size ceiling. Currently ~23 KB (the @noble suite dominates); the
 * headroom trips a real regression — a duplicate dependency, an errant Node
 * polyfill pulled into the browser bundle — without false alarms on @noble patch
 * bumps. Gzipped is the over-the-wire metric that matters for page load. The
 * build log prints the exact size. */
export const BUNDLE_BUDGET_GZIP_BYTES = 30_000;

async function main() {
  await build(bundleOptions);
  const bytes = await readFile(OUTFILE);
  const gzip = gzipSync(bytes, { level: 9 }).length;
  const kb = (/** @type {number} */ n) => (n / 1024).toFixed(1);
  console.log(
    `bundle ${OUTFILE}: min=${kb(bytes.length)}KB ` +
      `gzip=${kb(gzip)}KB (budget ${kb(BUNDLE_BUDGET_GZIP_BYTES)}KB gzip)`,
  );
  if (gzip > BUNDLE_BUDGET_GZIP_BYTES) {
    console.error(
      `bundle exceeds gzip budget: ${gzip} > ${BUNDLE_BUDGET_GZIP_BYTES} bytes`,
    );
    process.exit(1);
  }
}

// Build only when invoked directly (`npm run bundle`); a no-op when imported by
// the test, which drives esbuild itself in-memory.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

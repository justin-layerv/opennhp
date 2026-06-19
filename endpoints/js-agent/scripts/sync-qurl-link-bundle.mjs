// @ts-check
// Copies the production browser-agent bundle into the Terraform-served
// qurl-link asset directory and writes the matching Subresource Integrity value.
// Rebuilds first so qurl.link never syncs a stale dist/ artifact.
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { OUTFILE_PATH, buildProductionBundle, sriFor } from "./bundle.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "../../..");
const QURL_LINK_BUNDLE = resolve(
  REPO_ROOT,
  "terraform/modules/qurl-link/frontend/nhp-agent.min.js",
);
const QURL_LINK_SRI = `${QURL_LINK_BUNDLE}.sri`;

async function main() {
  const { bytes } = await buildProductionBundle();

  const integrity = sriFor(bytes);

  await mkdir(dirname(QURL_LINK_BUNDLE), { recursive: true });
  await copyFile(OUTFILE_PATH, QURL_LINK_BUNDLE);
  await writeFile(QURL_LINK_SRI, `${integrity}\n`, "utf8");

  console.log(`synced ${QURL_LINK_BUNDLE}`);
  console.log(`wrote ${QURL_LINK_SRI}: ${integrity}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

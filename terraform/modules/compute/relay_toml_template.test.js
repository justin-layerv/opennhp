"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const template = fs.readFileSync(path.join(__dirname, "relay.toml.tpl"), "utf8");
const computeModule = fs.readFileSync(path.join(__dirname, "main.tf"), "utf8");
const userDataTemplate = fs.readFileSync(path.join(__dirname, "user_data.sh.tpl"), "utf8");
const loopPattern = /%\{ for relay_pubkey in relay_trusted_public_keys_b64 ~\}([\s\S]*?)%\{ endfor ~\}/;

function canonicalKey(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.length === 32 && decoded.toString("base64") === value;
}

function canonicalTrust(current, additional) {
  const input = [current, ...additional];
  if (!input.every(canonicalKey)) throw new Error("malformed relay public key");
  if (new Set(additional).size !== additional.length) throw new Error("duplicate additional relay public key");
  if (additional.includes(current)) throw new Error("current relay public key duplicated in additional trust");
  return [...input].sort();
}

function render(keys) {
  const match = template.match(loopPattern);
  assert.ok(match, "relay template must contain the canonical public-key loop");
  const entry = match[1];
  const renderedEntries = keys.map((key) => entry.replaceAll("${relay_pubkey}", key)).join("");
  const rendered = template.replace(loopPattern, renderedEntries);
  assert.doesNotMatch(rendered, /%\{|\$\{/, "rendered fixture must not retain template directives");
  return rendered;
}

const oldKey = Buffer.alloc(32, 0).toString("base64");
const newKey = Buffer.alloc(32, 1).toString("base64");

describe("relay.toml public trust template", () => {
  it("renders two canonically ordered relay peers", () => {
    const rendered = render(canonicalTrust(oldKey, [newKey]));
    assert.equal((rendered.match(/^\[\[Relays\]\]$/gm) || []).length, 2);
    assert.ok(rendered.indexOf(oldKey) < rendered.indexOf(newKey));
  });

  it("is byte-identical when current and additional roles swap", () => {
    assert.equal(
      render(canonicalTrust(oldKey, [newKey])),
      render(canonicalTrust(newKey, [oldKey])),
    );
  });

  it("rejects malformed, duplicate, and current-in-additional inputs", () => {
    assert.throws(() => canonicalTrust("not-base64", []), /malformed/);
    assert.throws(() => canonicalTrust("AAAA", []), /malformed/);
    assert.throws(() => canonicalTrust(oldKey, [newKey, newKey]), /duplicate additional/);
    assert.throws(() => canonicalTrust(oldKey, [oldKey]), /duplicated in additional/);
  });

  it("chomps the nested render before the user-data heredoc adds its newline", () => {
    assert.match(computeModule, /relay_toml\s*=\s*var\.relay_enabled\s*\?\s*chomp\(templatefile\(/);
    assert.match(userDataTemplate, /\$\{relay_toml\}\nRELAYEOF/);
  });

  it("plan-fences the multi-line render inside its single-quoted heredoc", () => {
    const fence = computeModule.match(/resource "terraform_data" "relay_toml_render_fence" \{([\s\S]*?)\n\}/);
    assert.ok(fence, "multi-line relay TOML must retain a plan-time render fence");
    assert.match(fence[1], /count\s*=\s*var\.relay_enabled\s*\?\s*1\s*:\s*0/);
    assert.match(userDataTemplate, /<< 'RELAYEOF'\n\$\{relay_toml\}\nRELAYEOF/);
    assert.match(fence[1], /input\s*=\s*filesha256\("\$\{path\.module\}\/user_data\.sh\.tpl"\)/);
    assert.equal((fence[1].match(/precondition \{/g) || []).length, 2);
    assert.match(fence[1], /relay_toml exactly once as the body of the single-quoted RELAYEOF heredoc/);
    assert.match(fence[1], /must not interpolate the multi-line relay_toml value inside a bash comment/);
  });
});

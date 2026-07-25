"use strict";

// Regression fence for the nullable `auth_url` interpolation in the compute
// user_data template. `auth_url` is a nullable module input
// (modules/compute/variables.tf: `default = null`), so any `AuthUrl =
// "${auth_url}"` line that is NOT wrapped in a `%{ if auth_url != null ~}`
// guard makes `templatefile()` fail at plan time ("Cannot include a null value
// in a string template") for any consumer that leaves auth_url unset — even
// when `resource_mode = "api"` and the passcode plugin is enabled.
//
// The passcode plugin config.toml block previously interpolated AuthUrl
// UNCONDITIONALLY while its sibling SigningKey/AesKey lines (and the [server]
// config.toml AuthUrl) were already null-guarded. cell0 never hit it because
// the root coalesces auth_url null -> "" (terraform/main.tf), so the guard is
// byte-identical there (renders `AuthUrl = ""`); this fence keeps the guard
// from silently regressing for a future null-passing consumer.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const template = fs.readFileSync(path.join(__dirname, "user_data.sh.tpl"), "utf8");

// The passcode plugin config.toml heredoc body, rendered whenever the passcode
// plugin is enabled (independent of resource_mode / auth_url).
const passcodeBody = (() => {
  const m = template.match(/<< PLUGINEOF\n([\s\S]*?)\nPLUGINEOF/);
  assert.ok(m, "user_data must contain the passcode config.toml PLUGINEOF heredoc");
  return m[1];
})();

// A null-guarded AuthUrl line: `%{ if auth_url != null ~}` / AuthUrl / `%{ endif ~}`,
// matching the tilde form of the sibling SigningKey/AesKey guards in the same body.
const guardedAuthUrl =
  /%\{ if auth_url != null ~\}\nAuthUrl = "\$\{auth_url\}"\n%\{ endif ~\}/;

describe("user_data auth_url null-guard", () => {
  it("guards the passcode plugin AuthUrl exactly like its SigningKey/AesKey siblings", () => {
    assert.match(passcodeBody, guardedAuthUrl, "passcode AuthUrl must be null-guarded");
    // The siblings this guard was made consistent with must still be present.
    assert.match(passcodeBody, /%\{ if auth_signing_key != null ~\}\nSigningKey = "\$\{auth_signing_key\}"\n%\{ endif ~\}/);
    assert.match(passcodeBody, /%\{ if auth_aes_key != null ~\}\nAesKey = "\$\{auth_aes_key\}"\n%\{ endif ~\}/);
  });

  it("never interpolates the nullable auth_url without an immediately preceding null guard", () => {
    // Covers BOTH AuthUrl sites (passcode config.toml + [server] config.toml).
    // Every `AuthUrl = "${auth_url}"` line must sit directly under a
    // `%{ if auth_url != null ... }` directive (tilde optional — the two blocks
    // use different whitespace-trim styles).
    const lines = template.split("\n");
    const guardLine = /^%\{ if auth_url != null ~?\}$/;
    const authUrlLine = /^AuthUrl = "\$\{auth_url\}"$/;
    const sites = lines.reduce((acc, line, i) => (authUrlLine.test(line) ? [...acc, i] : acc), []);
    assert.ok(sites.length >= 2, "expected the passcode and [server] AuthUrl interpolation sites");
    for (const i of sites) {
      assert.match(
        lines[i - 1],
        guardLine,
        `AuthUrl interpolation on line ${i + 1} is not null-guarded — a null auth_url would fail templatefile() at plan time`,
      );
    }
  });
});

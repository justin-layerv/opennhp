# 2026-07-04 · qURL v2 browser knock in the qurl.link portal

- **Owner:** prod rollout coordinator
- **Scope:** nhp terraform (`modules/qurl-link` + root wiring) and the qurl.link
  frontend SPA. Adds the BROWSER-side qv2 (keyed-identity) knock: the portal now
  parses `#qv2.<claims>.<secret>.<sig>`, verifies the issuer signature locally
  against a shipped trust store, and knocks through the relay via the bundled
  `knockQurlV2`. Consumes the SAME issuer KMS key as the NHP-server trust store in
  `2026-07-01-qurl-v2-issuer-infra.md` (that entry owns the key + server side; this
  entry owns the portal). No js-agent source changed — the committed
  `nhp-agent.min.js` already exports `knockQurlV2`/`TrustStore`/`RelayAllowlist`.

The portal's `issuerTrustStore`/`relayAllowlist` are gated on the same root
`local.qurl_v2_admission_ready`, so they populate exactly when the server-side
trust store does. While that gate is off (all envs today) the rendered page is
qv1-only: the config keys are the empty `{}`/`[]` fail-closed form and a `#qv2.`
link shows the branded invalid-access page. The qv1 `at_`/`qv1.` path is
byte-for-byte unchanged (verified by rendering the pre-change template and
diffing the qv1 blocks).

Encoding contract to hold at enable: KMS/`data.aws_kms_public_key.public_key` is
**standard** base64 DER SPKI (the NHP server decodes it with `base64.StdEncoding`);
the browser `TrustStore.fromSpkiDerB64` decodes **strict unpadded base64url**, so
root `local.qurl_v2_issuer_public_key_der_b64url` rewrites `+/=`→`-_`+strip. Both
verifiers then trust the same DER bytes. A mismatch here means the portal rejects a
key the server accepts (or vice versa).

- [ ] **Rollout (this PR apply, any env):** the qurl.link CloudFront distribution
  re-renders `index.html` (new inline verifier bytes → new CSP script-src sha256
  hash; still exactly 2 inline executable scripts) and the root invalidation waiter
  blocks apply until the new bytes are live at every edge. Confirm the apply's
  `qurl-link CloudFront invalidation … completed` line, then GET `/` and confirm the
  page carries `handleQurlV2Fragment` and the `issuerTrustStore`/`relayAllowlist`
  config keys. The NHP-server + qurl-api fleets do NOT roll from this PR.
- [ ] **Pre-rollout (before qv2 links can OPEN in a browser):** everything in
  `2026-07-01-qurl-v2-issuer-infra.md`'s pre-rollout set (qurl-service admission
  routes deployed, contract-alignment set merged, server admission enabled). The
  portal only bootstraps the knock; the server still admits it. A `#qv2.` link
  cannot open until server-side admission works end-to-end.
- [ ] **Verify (sandbox, this PR apply):** sandbox already has qv2 admission ON
  (`qurl_v2_admission_enabled = true`, kid `qurl-issuer-sandbox-2026-07`), so
  `local.qurl_v2_admission_ready` is TRUE and this apply populates the sandbox
  portal. GET the deployed qurl.link `/` and confirm `issuerTrustStore` is a
  POPULATED object (not `{}`) carrying that kid and `relayAllowlist` carries
  `relay.qurl.link.layerv.xyz`. This PR already added sandbox to the smoke mirror
  `qurlLinkQurlV2EnabledEnvs`, so `tests/smoke/16_*` fences it both live
  (`TestQurlLinkFrontend_QurlV2ConfigPopulated`) and pre-deploy from the rendered
  template (`TestQurlLinkFrontend_QurlV2ConfigRendersPopulated`).
- [ ] **Verify (any FUTURE env enable, incl. prod):** when flipping another env's
  qv2 admission tfvars, add that env to `qurlLinkQurlV2EnabledEnvs` (kid + relay
  host) in the SAME change, then confirm its deployed `issuerTrustStore` populates
  with the matching kid — a bare `{}` on an enabled env means every qv2 link fails
  closed at the browser before any relay POST.
- [ ] **Post-rollout (real browser, at enable):** open a freshly-minted `qv2.` link
  in an actual browser and confirm it (a) clears the `#qv2.` fragment from history
  before verifying, (b) redirects to the protected resource, and (c) shows the
  invalid-access page — not a stuck spinner or the landing page — for a tampered
  fragment / unknown kid / off-allowlist relay_url. Headless-browser execution of
  these reject paths is still out of Go smoke scope (tracked with the qv1 gap in
  layervai/nhp#2748).
- [ ] **Rollback:** the portal follows the same gate as the server trust store —
  setting the qv2 admission flags back to false re-renders the page to the empty
  `{}`/`[]` qv1-only form on the next apply (a `#qv2.` link then fails closed).
  Existing minted `qv2.` links require a qv2-capable portal until revoked/expired.
- [ ] **Prod:** left dark. With qv2 admission unset in prod, the portal renders the
  empty fail-closed qv2 config and stays qv1-only.

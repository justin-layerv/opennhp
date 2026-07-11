# 2026-07-08 · Agent registration + email OTP (SES) · prod launch

- **Owner:** prod rollout coordinator
- **Source:** T1 (terraform: agent-registration SES + env + alarms). Cross-repo: qurl-service agent-reg (Q3 — `agent_otp_completed` / `agent_register_completed` slog + Config.Validate) and nhp relay OTP cap (`OTPRejectRateLimited`).

Adds the flag-gated agent email-OTP register surface to prod: the SES v2 sender
(DKIM + custom MAIL FROM + configuration set), the `QURL_AGENT_OTP_PEPPER` secret,
env plumbing on qurl-service (`QURL_AGENT_REGISTRATION_ENABLED`,
`QURL_AGENT_OTP_ENABLED`, `QURL_AGENT_OTP_EMAIL_FROM`, `QURL_NHP_RELAY_BASE_URL`,
`QURL_AGENT_OTP_PEPPER`) and nhp-server (`AGENT_OTP_REGISTRATION_ENABLED`), and the
CloudWatch alarms. Prod tfvars flips **both** PATH A (registration) and PATH B
(OTP) on; sandbox stays dark **for the SES/register surface** (both PATHs off, no
SES infra, no pepper, no slog-based register/OTP alarms). Note the one exception:
the OTP-shed alarm (`agent-relay-otp-reject-rate-limited`) still arms in sandbox
because it gates on `agent_otp_enabled || deploy_relay` and sandbox runs the relay
— `OTPRejectRateLimited` is emitted by every nhp-server, so a sandbox relay OTP-cap
trip pages sandbox SNS by design. **The OTP send-failed and OTP-shed alarms are
LAUNCH-BLOCKING — a wire failure (SES rejecting, OTP cap saturated) is silent to
the end user, who simply never gets a code.**

## ⚠️ MERGE = PROD LAUNCH (posture — read first)

**This PR ships the prod enable flags `true` (`agent_registration_enabled`,
`agent_otp_enabled`, `agent_otp_registration_enabled` are all `= true` in
`terraform/environments/prod/terraform.tfvars`) by an explicit keep-true
decision.** It is therefore NOT a dark-launch-then-flip: **merging this PR commits
to activation on the very next prod `terraform apply`** — including an apply
triggered by an unrelated change (a routine image bump), because the stale-
terraform gate forces `terraform/**` changes to apply. That first apply, in one
shot, creates the SES identity + DKIM/MAIL-FROM DNS + config set + pepper secret,
adds the OTP env vars to qurl-service, and rolls nhp-server user_data (~20-min
blue/green) — i.e. **real OTP emails to real users from `notify.layerv.ai`.**

Terraform preconditions check only flag COHERENCE; they CANNOT verify SES
production access or DNS propagation. So **the pre-merge human checklist below is
the real safety net** — a plan/apply will succeed against an unverified sender.

**HARD pre-merge gate — confirm ALL before merging (not before "flip"; there is no
separate flip step):**
- [ ] SES **production access** granted for `notify.layerv.ai` in **us-east-2** (out of the SES sandbox).
- [ ] **DKIM + MAIL-FROM DNS verified** for `notify.layerv.ai` (SES: domain Verified, DKIM Successful, `mail.notify.layerv.ai` MX resolves).
- [ ] OTP **pepper secret** (`${name_prefix}-agent-otp-pepper`) seeded (≥32 chars).
- [ ] **`relay.layerv.ai` reachable** if/when `deploy_relay` flips (prod keeps it `false` today; the register flow advertises this URL regardless).
- [ ] **Operator standing by** to watch the launch-blocking alarms on first real traffic (`-agent-otp-send-failed-spike`, `-agent-otp-bounce`).
- [ ] Merge is happening **inside the agreed launch window**.

**This supersedes the "staged flip / ships dark, flip PATH A then PATH B later"
framing in the ordered steps below** (kept as the operational sequence to WATCH
during/after the launch apply). Because the flags are already `true`, those PATH A
/ PATH B "flip … and apply" steps are not separate operator flips — they describe
what the single post-merge apply does and what to smoke-test at each layer, in
order. The SES-access + DNS prerequisites still gate the whole launch (below);
they are simply confirmed **before merge** now, not between two flips.

- [ ] Pre-rollout (HARD, before PATH B): **Request + confirm SES production access** for the sender domain (`notify.layerv.ai` — confirm the exact domain matches `agent_otp_email_from` in prod tfvars) in **us-east-2**. A new SES identity starts in the SANDBOX (send only to verified addresses, tiny quota) — this is a console/support action, not Terraform. With the identity still in sandbox, real customer OTP sends fail and surface as `agent_otp_completed outcome=send_failed` (the launch-blocking page).
- [ ] Pre-rollout (HARD, before PATH B): **Confirm DKIM + MAIL FROM DNS propagated + verified.** After the first apply creates the identity, the three EasyDKIM CNAMEs + the MAIL FROM MX/TXT land in the layerv.ai zone (`hosted_zone_id = Z0748438C8EK6UAW94ST`, cross-account layerv-mgmt, written via the `aws.route53_mgmt` provider like every other cross-account record). Verify SES shows the domain **Verified** and DKIM **Successful**, and that the MAIL FROM domain (`mail.notify.layerv.ai`) MX resolves — `behavior_on_mx_failure = REJECT_MESSAGE`, so a missing MX **rejects** sends rather than silently downgrading SPF alignment. (Cross-account write requires `cross_account_route53_role_arn` to be set for the env, as it already is for the existing qurl/connect/bootstrap DNS.)
- [ ] Rollout: **Populate `QURL_AGENT_OTP_PEPPER`** (the `${name_prefix}-agent-otp-pepper` Secrets Manager secret, ≥32 chars). Terraform creates the secret and seeds it out-of-band via `terraform_data.agent_otp_pepper_seed` (get-random-password 48 bytes, value never in state). NOTE: there is NO plan-time pepper `check` to look for — the earlier `agent_otp_pepper_populated` check was removed (it read the version back and forced `secret_string` into state, contradicting the never-in-state guarantee). The ≥32-char floor is instead guaranteed by (1) the 48-byte seed here and (2) qurl-service's boot `Config.Validate`, which rejects a <32-char `QURL_AGENT_OTP_PEPPER` fail-closed at startup. So just confirm the seed local-exec succeeded (no apply error); if you seed the value by hand instead, set it BEFORE the qurl-service task with `QURL_AGENT_OTP_ENABLED=true` starts, or the task refuses to serve OTP.
- [ ] Rollout (PATH A layer): `agent_registration_enabled` is already `true` in prod tfvars, so the post-merge apply activates PATH A automatically — this is NOT a separate operator flip. The apply adds `QURL_AGENT_REGISTRATION_ENABLED` + `QURL_NHP_RELAY_BASE_URL` to the qurl-service task def. **PATH A / internal register smoke:** exercise the internal agent-register credential-exchange path and confirm `agent_register_completed outcome=success`; watch the `*-agent-register-*` alarms stay green. (Env changes take effect on the next qurl-service CI deploy / force-new-deployment — trigger manually if the smoke needs it immediately.) `agent_registration_relay_base_url = https://relay.layerv.ai` is the committed launch value (keep-true decision); prod keeps `deploy_relay=false`, so it advertises the public relay, not a module reference — its reachability is a pre-merge checklist item above.
- [ ] Rollout (PATH B layer): `agent_otp_enabled = true` + `agent_otp_registration_enabled = true` are both already set in prod tfvars (the precondition requires them together), so the SAME post-merge apply that activates PATH A also activates PATH B — again NOT a separate flip. The apply adds `QURL_AGENT_OTP_ENABLED` + `QURL_AGENT_OTP_EMAIL_FROM` + `QURL_AGENT_OTP_PEPPER` on qurl-service and renders `AGENT_OTP_REGISTRATION_ENABLED` into nhp-server user_data (a fleet roll — ~20-min server blue/green). **PATH B / email OTP smoke:** request an OTP end-to-end, confirm delivery, then verify + register; confirm `agent_otp_completed outcome=success`. **Order matters — since there is no separate PATH B flip to withhold, the SES production access + DNS prerequisites (above) MUST be confirmed BEFORE MERGE**, or the first apply sends OTP from an unverified sender and every send fails closed.
- [ ] Post-rollout: watch the **launch-blocking alarms** for the first hours of real traffic: `${name_prefix}-agent-otp-send-failed-spike` (threshold 0 — first SES rejection pages) and, once the relay is live, `${name_prefix}-agent-relay-otp-reject-rate-limited` (the relay's **global 30/min OTP cap** across the whole fleet — the first reject pages; if it's genuine demand, raise the relay cap in relay code, don't just widen the threshold). Also watch the register brute-force alarms (`attempts-exceeded`, `credential-invalid`, `rate-limited`).
- [ ] Post-rollout (HARD — confirm the launch-blocking alarms are WIRED, not blind-green): every metric filter/alarm uses `treat_missing_data = notBreaching`, so a launch-blocking alarm sits **green whether the path is healthy OR the emitting code simply isn't live/matching yet** — a never-emitted metric, or a namespace/dim-set mismatch on the cross-repo `OTPRejectRateLimited` metric (its EMF dims are set by the **deployed nhp-server** metrics config, not this repo, so `terraform validate` cannot confirm the alarm's `{Environment}`-only dim set matches). The SES/DNS/pepper items above do NOT prove a datapoint lands. So for EACH launch-blocking metric, fire a canary and confirm ≥1 real sample arrives with the alarm's exact namespace+dims: induce a `send_failed` (unverified-sender send) and/or confirm a real delivery, a `bounce`, and (once relay live) an OTP-cap `reject`, and confirm `${name_prefix}-agent-otp-send-failed-spike`, `-agent-otp-bounce`, and `-agent-relay-otp-reject-rate-limited` each transition **out of `INSUFFICIENT_DATA`**. This is the only check that catches a never-emitted or mis-dimensioned launch-blocking page before real traffic depends on it (the cross-repo item below covers the *rename* risk; this covers the *never-emitted-yet / wrong-dims* risk).
- [ ] Rollback: set `agent_otp_enabled=false` + `agent_otp_registration_enabled=false` (PATH B) and/or `agent_registration_enabled=false` (PATH A) and re-apply. The env vars drop, user_data reverts (fleet roll), and the SES infra + pepper secret are destroyed (the secret has a 30-day prod recovery window). No qurl-service state migration to undo (register/OTP state is qurl-service-owned). If only disabling sends, flipping PATH B alone is enough and leaves the register path up.
- [ ] Cross-repo (HARD): the alarm filter patterns pin the EXACT slog `msg`/`outcome` strings qurl-service emits (`agent_otp_completed`/`agent_register_completed` with the frozen outcome vocab) and the nhp metric constant `OTPRejectRateLimited` (namespace `LayerV/NHP`, dim `Environment`; emitted from the shared OTP dispatch core in endpoints/server, so despite the relay-cap framing it is not relay-prefixed). If qurl-service renames an outcome/msg or nhp renames/redimensions the metric, the metric filter silently stops matching (0 samples, `notBreaching` keeps it green) and the launch-blocking page goes invisible — update both repos in lockstep and re-confirm a sample lands.

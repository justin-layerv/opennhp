# qurl-csp-gate-drift lint fixtures

Regression fixtures for `scripts/check-qurl-csp-gate-drift.sh`.

The lint fences drift between the qurl.link CSP propagation gate in
`.github/workflows/build-and-push.yml`, the smoke regex in
`tests/smoke/16_qurl_link_frontend_test.go`, the sandbox
`qurl_link_js_agent_enabled` tfvar, and the smoke sandbox origin default.

`run-fixtures.sh` generates small synthetic workflow, smoke, DNS, and tfvars
files for each case and invokes the lint through its four-argument override
interface. This keeps parser and equivalence regressions from hiding until a
real source edit happens to exercise them.

The lint also verifies the temporary legacy compatibility hashes against the
`e908489ee8d90a16075cd722a81191d7c23a1954` qurl.link HTML blob. In local
shallow clones, fetch that commit first:

```bash
git fetch --no-tags --depth=1 origin e908489ee8d90a16075cd722a81191d7c23a1954
```

## Fixtures

| Fixture | Expected exit | Why |
| --- | --- | --- |
| `in-sync` | 0 | Happy path: regexes, sandbox flag, and fallback origin agree. |
| `extra-sandbox-map` | 0 | An unrelated map with a `"sandbox"` key must not confuse the scoped smoke extractor. |
| `regex-drift` | 1 | Workflow and smoke regexes no longer accept the same CSP corpus. |
| `tfvar-drift` | 1 | Sandbox tfvars disable the JS-agent posture while smoke expects it. |
| `smoke-map-drift` | 1 | Smoke map disables the JS-agent posture while sandbox tfvars expect it. |
| `fallback-origin-drift` | 1 | Workflow fallback origin no longer matches the smoke sandbox origin. |
| `untranslated-posix-class` | 1 | A workflow regex adds a POSIX class the Python equivalence harness does not translate. |

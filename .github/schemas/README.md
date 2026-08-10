# Vendored JSON schemas

Third-party schemas committed here so CI validates against a local file
instead of fetching one at check time.

## `golangci.v2.11.jsonschema.json`

- **Upstream:** <https://golangci-lint.run/jsonschema/golangci.v2.11.jsonschema.json>
  (redirects to schemastore's `golangci-lint.json`; draft-07)
- **Fetched:** 2026-08-10, 169695 bytes,
  `sha256:985af311f9448d5b0964c3eda502204326dcf35d8f757192684cddc9b6615676`
  — recorded in the sidecar `.sha256` and **enforced** by the checker, so a
  local hand-edit cannot pass itself off as upstream's schema. Same idea as
  the `.sri` beside `terraform/modules/qurl-link/frontend/nhp-agent.min.js`.
- **Consumed by:** [`scripts/check-golangci-config-schema.py`](../../scripts/check-golangci-config-schema.py),
  run from `make lint-workflows` and `validate-workflows.yml`
- **Why vendored:** `golangci-lint-action` runs `golangci-lint config verify`
  by default, which fetches this schema over the network on every run. All
  four `lint (...)` matrix legs verify the same `.golangci.yml`, so one
  timeout against `golangci-lint.run` reds the whole matrix in 7-15s. The
  action now sets `verify: false`.

  The verification itself is not expendable: `golangci-lint run` **silently
  ignores** unknown top-level and unknown nested config keys — only a
  misspelled *linter name* errors — so a typo'd key reads as an enabled
  setting that does nothing.

  `config verify` cannot be pointed at a local copy: there is no `--schema`
  flag, and a `$schema` key in `.golangci.yml` is rejected as an unknown
  property rather than honoured.

### Refreshing

The upstream URL is major.minor-scoped, so this file only needs refreshing
when the `version:` pin on the `golangci/golangci-lint-action` step in
`.github/workflows/ubuntu-build.yml` crosses a **minor** boundary
(`v2.11.4` → `v2.11.9` reuses this file; `v2.12.0` needs a new one).

`check-golangci-config-schema.py` fails with the exact `curl` command when
the pin moves ahead of what is vendored, so a bump cannot land without it.
Delete the superseded file in the same change.

```bash
curl -sSfo .github/schemas/golangci.v2.12.jsonschema.json \
  https://golangci-lint.run/jsonschema/golangci.v2.12.jsonschema.json
shasum -a 256 .github/schemas/golangci.v2.12.jsonschema.json \
  | awk '{print $1}' > .github/schemas/golangci.v2.12.jsonschema.json.sha256
```

The refreshed schema must be **self-contained** — no `$ref` to an `http(s)`
URL. `jsonschema` resolves refs lazily and would fetch one at check time,
putting the network back on the path this vendoring removed, where it would
look like a flake rather than a regression. The checker rejects remote refs, so
a refresh that introduces one fails rather than silently going online.

**Known limitation.** Pinning to a local copy means an upstream in-place
correction *within* the same major.minor never reaches us. That is inherent to
vendoring, and it is the trade being made deliberately: a reproducible local
artifact instead of a third-party host on the critical path of every Go PR.
Re-fetch when you want the correction.

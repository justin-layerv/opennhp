//go:build smoke

// Package smoke contains live-environment smoke tests for the NHP server and
// Access Controller. Unlike unit, local, integration, and e2e tests, these
// tests run against a deployed sandbox or prod environment and verify
// NHP's own contract clauses against the binary that is actually running.
//
// # Layers
//
//	unit        — process, no I/O ("does this function do what it says?")
//	local       — docker compose + ephemeral processes ("do components wire up?")
//	integration — live etcd + NLB UDP + certs ("is the plumbing alive?")
//	e2e         — public console HTTP ("does the legacy demo still work?")
//	smoke (this) — deployed nhp-server + ac + qurl-api
//	             ("is every NHP contract clause intact against the deployed binary?")
//
// # Tiers
//
// Tests are organized into three tiers, each with a dedicated file-name prefix
// so go test runs them in a deterministic order:
//
//	Tier 1 (01-09): regression guards for fenced bug classes.
//	                Must pass or the deploy did not deploy what we think it did.
//	Tier 2 (10-19): consumer contract — every guarantee NHP makes to its callers
//	                (QURL plugin, Traefik plugin, the wire protocol).
//	Tier 3 (20-29): NHP capability coverage and informational telemetry.
//
// PR1 ships Tier 1 only. Tier 2 and Tier 3 land in follow-up PRs after the
// harness has proven stable in CI.
//
// # Running
//
// All contexts go through scripts/run-smoke.sh (TARGET=local|sandbox|prod) —
// the single entrypoint shared by local pre-PR runs, PR CI, and post-deploy
// CI. It owns the tier -> RUN_FILTER mapping and the env-derived flags.
//
// Local self-contained stack — no AWS, no Auth0. Brings up nhp-server +
// nhp-ac + dynamodb-local via docker compose (tests/smoke/local-stack; the AC
// registers with a seeded license so knock-ready reflects a live peer) and
// runs the wire-contract `local` tier against the freshly-built binaries:
//
//	make test-smoke-local              # or: TARGET=local ./scripts/run-smoke.sh
//
// Against the deployed sandbox/prod — reads the AWS profile (no Auth0: the
// qURL-minting tests that needed it were moved out of nhp — qURL smoke
// belongs in qurl-service, see tests/smoke/CLAUDE.md):
//
//	make test-smoke-sandbox            # AWS_PROFILE=layerv,      all tiers
//	make test-smoke-prod               # AWS_PROFILE=layerv-prod, all tiers
//
// Compile + vet only (the credential-free PR gate, also a CI job):
//
//	make smoke-build
//
// # Environment variables
//
// Required:
//
//	NHP_ENVIRONMENT            local | sandbox | prod
//	AWS_REGION                 us-east-2 (sandbox/prod; ignored by local)
//
// The local target derives localhost endpoints (NHPServerBaseURL =
// http://localhost:8888 by default; override with NHP_SERVER_BASE_URL) and
// skips AWS deploy-mode discovery entirely.
//
// Optional (defaults derived from NHP_ENVIRONMENT — see dns.go):
//
//	NHP_SERVER_BASE_URL        nhp-server NLB endpoint, e.g.
//	                           https://resolve.qurl.link.layerv.xyz (sandbox)
//	                           https://resolve.qurl.link             (prod)
//	                           NOT api.layerv.* — that's the QURL API.
//	QURL_API_BASE_URL          qurl-service API host the public-ALB lockdown
//	                           fence targets, e.g. https://api.layerv.xyz
//	NHP_SMOKE_ALLOW_SSM_PROBES true in sandbox, false in prod during burn-in
//
// Blue/green context (active color, per-color ASG names, TG ARNs,
// listener ARNs) is read directly from SSM at test time from
// /{env}/nhp/{server,ac}/*. No env vars needed — the workflow does not
// pre-resolve these, and local runs work the same way as CI.
//
// # Capability map (file → NHP capability)
//
//	01_health_test.go              Health endpoints (/live, /ready, /knock-ready, /startup)
//	02_docker_image_test.go        nhp-server Docker image contents
//	03_ssm_runbook_test.go         SSM RunShellScript deploy runbook invariants
//	04_blue_green_state_test.go    Blue/green listener + SSM + ASG consistency
//	05_ac_eip_pool_test.go         AC Elastic IP pool sizing + coverage
//
// # Maintenance rules (enforced at review)
//
//  1. One file per NHP capability. New capability ⇒ new file.
//  2. Every test name references a capability or a bug class.
//  3. Every Tier 1 test has a Go comment tagging the PR whose regression it fences.
//  4. SSM probes are named helpers. No dynamic command strings.
//  5. Deletion is a valid PR — structural elimination of a bug class retires a fence.
//
// The full rules live in tests/smoke/CLAUDE.md, "Smoke Test Suite".
package smoke

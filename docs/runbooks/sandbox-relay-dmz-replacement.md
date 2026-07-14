# Sandbox Relay DMZ Deployment and Verification

This runbook deploys the sandbox stateless relay as an HTTPS-only DMZ service.
It does not move native UDP onto the relay and does not remove the public NHP
server NLB used by assigned UDP SDKs.

## Target topology

- Relay public ingress: ALB HTTPS 443 only.
- Relay instances: isolated subnets, no public IP, NAT, or default route.
- Relay backend: HTTPS 8080 from the ALB SG.
- Browser-relay private hop: relay UDP 62206 to the internal server NLB.
- Authenticated return: server SG to relay UDP 62207, private only.
- UDP SDK ingress: assigned-cell public server NLB, UDP 62206 only.

Production remains relay-dark until its separate production review and plan.

## Preconditions

1. Record the reviewed commit SHA and image tag.
2. Confirm the matching server build is deployed before refreshing the relay.
3. Confirm the assigned cell's public server NLB and its UDP 62206 listener are
   healthy. Do not proceed if UDP 62207 or a second UDP listener is present.
4. Confirm the relay identity secret/public-key registration and the exact main
   private-subnet CIDRs are unchanged.
5. Record named security approval of the UDP 62207 return-side residual: an
   SG-reachable sender can consume one synchronous, bounded Noise decrypt before
   the configured server-key fingerprint allowlist rejects an unknown key. The
   approver must confirm both the server-SG-only ingress rule and post-decryption
   allowlist remain load-bearing.
6. Create a dedicated evidence directory and retain every plan/check/smoke log,
   including the approval from step 5.

```bash
export REVIEWED_SHA=<commit>
export REVIEWED_IMAGE_TAG=<tag>
export RELAY_DMZ_EVIDENCE_DIR=<absolute-evidence-directory>
mkdir -p "$RELAY_DMZ_EVIDENCE_DIR"
```

## Gate 1: normal CI deployment

The initial sandbox DMZ cutover completed through CI on 2026-07-13. A merge to
`main` now runs the normal deployment automatically. To re-run it explicitly,
dispatch the workflow from `main`; it assumes the sandbox GitHub OIDC role,
generates a saved Terraform plan, exports its JSON, and checks that every
fenced DMZ boundary address is a no-op before applying that exact artifact.

```bash
gh workflow run build-and-push.yml --ref main \
  -f environment=sandbox \
  -f deploy=true \
  -f skip_tests=false \
  -f force_build=false
```

There is no standing cutover override. The plan must retain the assigned-cell
public server NLB and its sole UDP 62206 listener/target group, the internal UDP
62206 listener, and the HTTPS-only relay ALB while showing no relay NLB or
public UDP 62207. Any future boundary migration must add a newly reviewed,
temporary mechanism. The same job runs structural convergence and a full
post-apply no-op plan.

## Gate 2: structural proof

Run the live detector after apply. Schema v9 proves the relay owns only its
HTTPS ALB/target group, that the peered assigned cell has exactly one NHP-owned
public UDP-capable listener on 62206, and that the internal relay listener points
to healthy targets in the same active-color server ASG.

```bash
python3 scripts/check-relay-dmz-live.py --environment sandbox --mode structural \
  | tee "$RELAY_DMZ_EVIDENCE_DIR/structural.json"
```

Also inspect ELB listeners and server/relay SGs directly. The evidence must show:

- relay ALB HTTPS 443 only;
- no internet-facing relay NLB or relay UDP listener;
- assigned-cell server NLB UDP 62206 exactly once;
- internal server NLB UDP 62206 points to healthy active-color targets using the
  canonical server SG;
- no public UDP 62207 listener;
- relay UDP 62206 egress only to reviewed private CIDRs;
- relay UDP 62207 ingress only from the server SG.

## Gate 3: relay fleet and HTTPS proof

The workflow refreshes the canonical relay ASG to the reviewed image and then
runs functional validation. Functional target health covers the HTTPS target
group only. The detector can be repeated independently as a read-only check:

```bash
python3 scripts/check-relay-dmz-live.py --environment sandbox --mode functional \
  | tee "$RELAY_DMZ_EVIDENCE_DIR/functional.json"
```

Run a real external browser/JS-agent request against the relay HTTPS endpoint
and retain the transcript, request ID, relay log, and server return evidence.

## Gate 4: direct SDK UDP proof

From a host outside every LayerV VPC, use a real NHP UDP SDK/agent against the
public NHP server NLB of the test assignment's cell on UDP 62206. Retain the
assignment response, resolved NLB endpoint, client transcript, server request
ID, and resulting authorization evidence.

Do not point this smoke at the relay ALB or any relay DNS output. UDP silent
drop is not sufficient negative proof for 62207; use ELB listener inventory,
SG inventory, and Flow Logs to prove it is not publicly accepted.

## Gate 5: idempotency and evidence

The deployment workflow creates a full post-apply plan and checks its JSON with
`--require-pr0-applied --require-dmz-boundary-noop`. Every fenced relay-DMZ
boundary address must be a no-op. Unrelated provider- or CI-owned resources may
still appear in the full-stack plan; they do not weaken this boundary-specific
idempotency proof and remain owned by their normal drift workflows. Archive:

- reviewed SHA and image digest;
- saved plan and plan JSON;
- structural and functional detector output;
- relay HTTPS smoke;
- assigned-cell external UDP 62206 smoke;
- listener/SG/Flow proof that public UDP 62207 is absent;
- named UDP 62207 return-side residual-risk approval;
- post-apply plan JSON proving every relay-DMZ boundary address is a no-op.

## Rollback

Rollback of the relay DMZ affects the browser HTTPS path only. Revert to the
last reviewed relay image/config and re-run structural plus functional checks.
Do not delete, disable, or repoint the assigned-cell public server NLB: it is an
independent SDK ingress surface.

If the saved plan changes the public server NLB, UDP listener, or server SG in a
way not explicitly reviewed for direct SDK ingress, stop and obtain a new plan
review rather than applying or attempting an ad-hoc rollback.

## Issue #3184

[#3184](https://github.com/layervai/nhp/issues/3184) tracks direct assigned-cell
server-edge availability under spoofed UDP floods. It must be resolved before
production rollout of UDP SDK traffic, but is not a blocker for the HTTPS-only
relay deployment while no UDP SDK users exist.

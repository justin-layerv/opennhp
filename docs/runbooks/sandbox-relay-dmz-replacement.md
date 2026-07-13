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
5. Create a dedicated evidence directory and retain every plan/check/smoke log.

```bash
export REVIEWED_SHA=<commit>
export REVIEWED_IMAGE_TAG=<tag>
export RELAY_DMZ_EVIDENCE_DIR=<absolute-evidence-directory>
mkdir -p "$RELAY_DMZ_EVIDENCE_DIR"
```

## Gate 1: reviewed saved plan

Generate one saved sandbox plan under GitHub OIDC, export its JSON, and run the
DMZ contract checker against that exact artifact. Review all creates, updates,
and destroys. The plan must retain the compute module's public server NLB,
public UDP 62206 listener/target group, and internal UDP 62206 listener while
showing no relay NLB, relay UDP listener, or relay-native alarm/DNS resources.

```bash
export RELAY_DMZ_PLAN="$RELAY_DMZ_EVIDENCE_DIR/relay-dmz.tfplan"
terraform -chdir=terraform/environments/sandbox plan -out="$RELAY_DMZ_PLAN"
terraform -chdir=terraform/environments/sandbox show -json "$RELAY_DMZ_PLAN" \
  > "$RELAY_DMZ_EVIDENCE_DIR/relay-dmz.tfplan.json"
python3 .github/scripts/check-relay-dmz-plan.py \
  "$RELAY_DMZ_EVIDENCE_DIR/relay-dmz.tfplan.json"
```

Apply only the saved artifact that passed review:

```bash
terraform -chdir=terraform/environments/sandbox apply "$RELAY_DMZ_PLAN"
```

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

Refresh the relay to the reviewed image using the deployment helper, then run
functional validation. Functional target health covers the HTTPS target group
only.

```bash
.github/scripts/deploy-relay.sh sandbox true "$REVIEWED_IMAGE_TAG"
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

Create a new post-apply plan. It must be empty, and the plan checker must pass
with the boundary-noop option used by the deployment workflow. Archive:

- reviewed SHA and image digest;
- saved plan and plan JSON;
- structural and functional detector output;
- relay HTTPS smoke;
- assigned-cell external UDP 62206 smoke;
- listener/SG/Flow proof that public UDP 62207 is absent;
- post-apply empty plan.

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

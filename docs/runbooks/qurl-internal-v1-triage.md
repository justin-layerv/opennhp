# Runbook: Debugging qurl-service `/internal/v1/*` from a laptop

`/internal/v1/*` is no longer reachable from the public internet
(`api.layerv.{xyz,ai}/internal/*` returns 404 — qurl-service #335 PR4).
It serves only on the internal ALB at `internal-api.qurl.layerv.{xyz,ai}`,
which resolves only inside the VPC via the workload-account private
hosted zone.

To curl an internal endpoint for triage:

```bash
# 0. Set ENV first — it parameterizes the AWS profile, the instance
#    tag filter, the secret name, AND the internal hostname. Hard-
#    coding any one of these breaks the prod path on copy-paste.
ENV=sandbox  # or "prod"
PROFILE=$([ "$ENV" = "prod" ] && echo "layerv-prod" || echo "layerv")
TLD=$([ "$ENV" = "prod" ] && echo "ai" || echo "xyz")

# 1. Find any private-subnet NHP-server EC2 in the target env. The
#    no-instances guard catches a tag-filter typo or an ASG-scaled-
#    to-0 incident state — without it, step 2 silently runs against
#    the placeholder `i-XXXXX` literal.
INSTANCE=$(AWS_PROFILE=$PROFILE aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*${ENV}*server*" \
            "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].InstanceId' \
  --output text | tr '\t' '\n' | head -1)
[ -n "$INSTANCE" ] || { echo "ERROR: no running NHP server instances in $ENV" >&2; exit 1; }

# 2. SSM session
AWS_PROFILE=$PROFILE aws ssm start-session --target "$INSTANCE"

# 3. Inside the session — fetch service token from Secrets Manager.
#    The NHP server EC2 role grants secretsmanager:GetSecretValue on
#    var.qurl_service_token_secret_arn (verified at
#    terraform/modules/compute/main.tf:465), so this curl works
#    in-session without additional IAM scoping.
#
#    Fail-safe shape detection across two shapes only:
#      (a) today's raw plaintext, or
#      (b) an explicit `{"token": "..."}` envelope after a future
#          migration. The `jq -er '.token'` branch fail-fasts on a
#          non-`.token` envelope and the fallback preserves today's
#          plaintext behavior. Any OTHER JSON shape (e.g., `.value`,
#          `.secret`, `.data.token`) is then explicitly rejected by
#          the case-statement guard below — this prevents curl
#          proceeding with a literal JSON object as the
#          X-Service-Token header, which would produce a confusing
#          401 at the handler. If the envelope is ever migrated to a
#          shape other than `.token`, update the jq filter here.
# jq isn't shipped on AL2023 by default; if cloud-init didn't
# install it, the `jq -er '.token' 2>/dev/null` invocation below
# would silently fall through to TOKEN_RAW for ANY shape (not just
# plaintext) — defeating the envelope-detection guard. Surface
# the missing dep explicitly first.
command -v jq >/dev/null 2>&1 || {
  echo "ERROR: jq is not installed in this SSM session. Install via your distro's package manager (AL2023/RHEL: sudo dnf install -y jq; Debian/Ubuntu: sudo apt-get install -y jq) or update cloud-init to bake it in. Without jq the envelope-shape detection below cannot run." >&2
  exit 1
}
TOKEN_RAW=$(aws secretsmanager get-secret-value \
  --secret-id "layerv-nhp-${ENV}/qurl-internal-service-token" \
  --query SecretString --output text)
TOKEN=$(printf '%s' "$TOKEN_RAW" | jq -er '.token' 2>/dev/null || printf '%s' "$TOKEN_RAW")
case "$TOKEN" in
  '{'*|'['*)
    echo "ERROR: secret envelope shape changed (TOKEN starts with JSON delimiter). Update the jq filter at docs/runbooks/qurl-internal-v1-triage.md \"qurl-internal-service-token\" — likely a key other than .token (e.g., .value, .secret, .data.token)." >&2
    exit 1
    ;;
esac

# 4. Curl
curl -H "X-Service-Token: $TOKEN" \
  "https://internal-api.qurl.layerv.${TLD}/internal/v1/resource/r_xxx/target"
```

Public-resolver test (verify hostname is NOT externally resolvable).
**Both `.xyz` (sandbox) and `.ai` (prod) probed regardless of `ENV`** —
the test is "no env's internal hostname has leaked to the public zone,"
not "this env's hostname is private," so we want both reading
NXDOMAIN every time.

```bash
dig internal-api.qurl.layerv.xyz @1.1.1.1   # must return NXDOMAIN
dig internal-api.qurl.layerv.ai  @1.1.1.1   # must return NXDOMAIN
```

If either resolves, a record has leaked into the public zone — file a
P0 incident.

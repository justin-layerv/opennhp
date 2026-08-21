# Connector Control Terraform roots

These roots own the environment-global Connector Authority foundation and
Connector Hub artifact boundary in a state that is deliberately separate from
every NHP cell:

- sandbox: `nhp/sandbox/control/terraform.tfstate`
- production: `nhp/prod/control/terraform.tfstate`

They must never import or reference the legacy cell0 state. The exact global
resource/table prefix is `layerv-nhp-<env>-control`; cell stacks retain
`layerv-nhp-<env>-<cell_id>`.

The foundation is dark. It creates no Lambda function, alias, runtime caller
role, Hub worker/listener, load balancer, DNS record, plugin, public HTTP route,
or runtime activation. The Hub repository, digest pin, and publisher role are
artifact prerequisites only; the Hub build matrix remains `publish: false`.
Interface and DynamoDB endpoints start with deny-all
policies, and their security groups have no ingress. A later reviewed runtime
slice must replace both boundaries in lockstep with exact qualified alias ARNs
and operation-specific identities. Because private DNS is already enabled,
in-VPC AWS SDK service names resolve to these endpoints: changing only the
endpoint policy or only security-group ingress would route calls privately and
fail them at the boundary.

The nullable `authority_runtime_contract` root input is also dark. Production
keeps the module's internal evidence-verification latch false and requires the
contract to remain null. The sandbox wrapper opens the latch only when the
permanent exact-main workflow supplies a generated contract whose canonical
manifest bytes, stable blob-owning commit, schema, environment, AWS identities,
function graph, and capacity algebra have all been verified. Conditional SSM
and ECR reads then bind that contract to the publisher-owned digest sentinel and
the exact immutable image. The versioned object freezes provisioned-cell,
operation, concurrency, request-rate, color, and evidence shapes without
creating a function or caller path or accepting caller-supplied evidence as
proof. Null inputs remain absent from the persisted
`terraform_data.foundation_contract` input and root output surfaces; an enabled
sandbox contract creates one reviewed contract-only state transition and
requires the attended Control rollout workflow.

When the independent runtime gate is enabled against the verified sandbox
contract, the module deploys the contract's complete graph: three Hub
operations plus `iro/ar/cr/ccr/creso` for every provisioned cell. The current
two-cell basis therefore creates 13 functions and 26 closed blue/green aliases.
On this initial dark bootstrap, both colors intentionally point at the same
first published version and only the selected color is provisioned. This is not
yet a working blue/green image-roll or rollback path: the contract's rollout
capacity and rollback-retention fields remain validation-only until
[nhp#3456](https://github.com/layervai/nhp/issues/3456) lands, which blocks the
first post-bootstrap Authority image roll and every production activation.
Execution IAM and private endpoint policies are operation-specific: IA alone
signs; IRO/AR alone receive OTP secret and directional Redis access; IRO alone
sends SES email. The cell callers do not use this Control VPC's Lambda
endpoint—their own VPC stacks create private-DNS endpoints restricted to their
five exact same-color aliases. Production remains locked dark until its
separate catalog, evidence, and rollout review exist.

The one non-runtime cross-repository identity is the dedicated Connector
Authority image publisher role. Sandbox trusts only the
`repo:layervai/qurl-service:environment:sandbox` GitHub OIDC subject;
production trusts only
`repo:layervai/qurl-service:environment:production`. Its inline policy can
obtain the unavoidable account-wide ECR authorization token, push/read and
verify manifests only in `layerv/qurl-connector-authority`, and get/put only
`/<env>/nhp/control/connector-authority/image-digest`. It cannot operate
Lambda or access Control data, network, KMS, Redis, or SES resources. The
qurl-service publication workflow must derive a registry-confirmed canonical
lowercase `sha256:<64hex>` digest, validate that exact shape immediately before
the SSM write, and read the parameter back exactly; IAM can scope the parameter
ARN but cannot constrain its value.

NHP has a separate, equally narrow Hub publisher role. Sandbox trusts only
`repo:layervai/nhp:environment:hub-publish-sandbox`; production trusts only
`repo:layervai/nhp:environment:hub-publish-production`. The ordinary shared
`sandbox` and `production` deployment Environments are deliberately not
admitted. Before either publisher role can be used, the matching dedicated
`hub-publish-sandbox` or `hub-publish-production` GitHub Environment must be
configured with a `main`-only deployment branch policy and required human
review. Publication must remain impossible until a live GitHub settings
readback proves both protections for the exact Environment; repository code
and an Environment name alone are not proof. The carrier must repeat that
readback as a fail-closed preflight before every publication attempt and reject
a missing required reviewer Justin (`178750268`), any branch policy other than
the sole custom `main` policy, or either shared deployment Environment name.

The 2026-07-23 live readback established both dedicated Environments with
required reviewer Justin (`178750268`), a sole custom `main` deployment branch
policy, `can_admins_bypass=true`, and `prevent_self_review=false`; the shared
`sandbox` and `production` Environments were unchanged. These observed settings
do not replace the per-publication preflight. This is deliberately a
single-operator approval and audit checkpoint, not a two-person-control or
malicious-repository-admin boundary: the same trusted operator may dispatch and
approve, and a trusted repository admin retains GitHub's emergency bypass.
The load-bearing controls against accidental publication, and for the ordinary
reviewed path, remain the manual exact-live-`main` dispatch, source-SHA
confirmation, dedicated Environment OIDC subject, sole `main` branch policy,
and exact publisher-role scope. The checker intentionally permits either
boolean to become stricter later without a carrier change; widening reviewer or
branch policy still fails closed.

The role can push/read and verify
manifests only in `layerv/nhp-hub` and get/put only
`/<env>/nhp/control/hub/image-digest`; it has no Control-runtime, network,
KMS, or cell permissions. The repository is KMS-encrypted, immutable, and
scan-on-push. Its lifecycle expires only untagged uploads after seven days, so
source-SHA rollback artifacts remain available. A later reviewed publication
carrier must declare the exact dedicated protected GitHub Environment, refuse
shared `sandbox` or `production`, publish only the source SHA, use the role's
read-only `DescribeImageScanFindings` grant to prove scan success, and then
write/read back the canonical digest pin. Do not publish `latest` or
environment tags. Do not configure the carrier role reference or enable its
publication gate before the live protection readback passes.

SES identity/configuration-set ownership is intentionally excluded from this
slice because sandbox already owns those resources in the legacy state. The
ordered no-delete/no-dual-ownership transfer is tracked in
[nhp#3273](https://github.com/layervai/nhp/issues/3273).

## CIDR selection evidence

The 2026-07-16 live preflight in `us-east-2` used
`scripts/check-control-vpc-cidr-overlap.sh` and found:

- sandbox account `767397897469`: existing IPv4 VPC CIDRs
  `10.100.0.0/16`, `10.101.0.0/16`, and `172.31.0.0/16`; one active
  `10.101.0.0/16` to `10.100.0.0/16` peering; no VPC IPAM, Transit Gateway,
  nondeleted VPN, Client VPN, Direct Connect connection, or Direct Connect
  virtual-interface resources. Active non-default IPv4 routes added no remote
  CIDRs beyond those VPC/peering ranges. Candidate `10.102.0.0/16` passed.
- production account `235500187906`: existing IPv4 VPC CIDRs
  `10.200.0.0/16` and `172.31.0.0/16`; no active VPC peering, VPC IPAM,
  Transit Gateway, nondeleted VPN, Client VPN, Direct Connect connection, or
  Direct Connect virtual-interface resources. Active non-default IPv4 routes
  added no remote CIDRs. Candidate `10.202.0.0/16` passed.

The reviewed `/16` VPC inputs produce three `/24` isolated subnets through
`cidrsubnet(..., 8, ...)`; input validation permits at most `/20`, guaranteeing
the resulting subnets are never narrower than `/28`.

The rollout ledger requires the same fail-closed preflight immediately before
each first apply. If IPAM, Transit Gateway, VPN, or Direct Connect resources
appear, the script refuses to approve the CIDR until their routed allocations
are audited. Treat any CIDR parse failure the same way: stop and audit the
reported allocation rather than weakening or bypassing strict parsing.

Do not rerun the same candidate check after the Control VPC exists: its own
associated CIDR will correctly appear as an overlap. Use ordinary Terraform
plan/drift verification after the first apply.

The script is intentionally scoped to the target AWS region (`us-east-2`).
Before accepting either CIDR, the rollout owner must also enumerate every
enabled account region and audit cross-region VPC peering, Transit Gateway
peering, IPAM, VPN, and Direct Connect gateways, gateway associations, and
other paths for remote CIDRs. A passing local preflight is not proof about
out-of-region or Direct Connect gateway routing.

The Control CIDR is not a reusable "next cell" allocation. A later cell1 root
initially reused `10.102.0.0/16`; that did not create reachability because
Control and cell VPCs have no route, peering, Transit Gateway, or shared
security group. Even so, overlapping VPCs unnecessarily foreclose unambiguous
future private routing. The 2026-07-25 replacement audit rejected
`10.103.0.0/16` because the UDP proof runner already owns `10.103.0.0/28`,
then accepted cell1 `10.104.0.0/16` across all 17 enabled sandbox regions.
Every regional inventory found no overlapping VPC/route/peering allocation and
no active IPAM, Transit Gateway attachment, VPN, Client VPN, Direct Connect
connection, or virtual interface; the separate global reads found no Direct
Connect gateway and no Cloud WAN core network. Cell1 is pinned to
`10.104.0.0/16` and requires a new all-region audit before any later change.

## PrivateLink service evidence

The 2026-07-16 pre-apply check queried EC2 endpoint-service discovery in both
environment accounts. `com.amazonaws.us-east-2.email` exists as an Interface
service in `us-east-2a`, `us-east-2b`, and `us-east-2c` in sandbox and
production. The authority uses that SES API service for SDK `SendEmail` calls;
it does not use the separate `email-smtp` service.

## Apply-role evidence

The 2026-07-16 IAM simulator check evaluated `iam:PassRole` from the live
`nhp-<env>-github-actions` role to the exact
`layerv-nhp-<env>-control-vpc-flow-logs` role ARN. Sandbox and production both
returned `allowed`, matched by their respective
`nhp-<env>-github-actions-terraform-apply-iam` policies, with no missing
context. Rerun this check if apply-role scoping changes before first apply.

The shared `nhp-<env>-github-actions` apply role intentionally also gains the
ElastiCache user and user-group lifecycle/tag actions required by this root.
Those actions are isolated in `ElastiCacheControlRBAC` and scoped to only the
current environment's `layerv-nhp-<env>-control-*` user and user-group ARNs;
they cannot manage cell-scoped Redis identities. PR CI only plans the control
root and now requires the converged foundation to remain an exact no-op unless
an intentional update revises that policy and its tests in the same PR.
`CreateServerlessCache` and `ModifyServerlessCache` also authorize the cache's
referenced user group as a dependent resource. The separate
`ElastiCacheControlCacheUserGroupDependency` statement grants only those two
actions on the exact `layerv-nhp-<env>-control-otp-users` ARN; it grants no
delete action and cannot associate a cell user group. The attended preflight
used for sandbox bootstrap simulated the complete cache-plus-user-group
resource matrix for both the allowed Control group and a denied cell group; its
self-simulation grant was removed with the one-time workflow. The
repository-wide IAM coverage gate maps every new resource type to the complete
provider action set, and the rollout owner must simulate the exact scoped
actions before first apply. A policy-structure test pins both the complete
action set and the two environment-global resource patterns.

A resource postcondition fails plan before the 6,144-character managed-policy
limit is crossed. The foundation's grants fit within existing policies and add
no attachment. The 2026-07-16 live roles had 10 attached policies in sandbox
and 8 in production; the static
worst-case counter is 10 of 10 because it conservatively includes every
conditional attachment. Treat attachment runway as zero across the shared
module: future grants must consolidate within an existing policy or pair a
new attachment with an intentional consolidation/quota plan.

The two publisher roles and their inline policies require no expansion of that
shared apply role: its existing `IAMRoles` statement already admits the
`layerv-nhp-*` role namespace and the IAM role/policy lifecycle actions that
Terraform needs. Repository contract tests pin that prerequisite; no publisher
permission is added to the shared role.

## CI and live-state semantics

The PR control plan uses `-refresh=false` with the narrow read-only plan role.
That proves the proposed configuration and plan contract, but after first apply
it does not prove live-state drift. First apply, post-apply verification, and
later operational changes require a refresh-enabled plan from the reviewed
apply path.

The plan contract rejects every action set containing `delete`, including a
Terraform replacement (`delete,create`). That remains intentional after the
foundation is live. It admits only three exact transition families: Authority
publisher role/policy creation (including the policy-only partial retry), the
43-to-45 Redis split (either or both split-user creates plus the exact legacy
user-group membership replacement), and the five-create Hub artifact bootstrap
(repository, untagged-only lifecycle, `UNPUBLISHED` digest pin, publisher role,
and inline policy, including dependency-safe partial retries). The transitions
cannot be combined. Once they are complete, the same exact 50-resource contract
must be a no-op. The checker separately admits only the provider's exact
refresh-only role-policy reflection and externally owned Authority/Hub digest
value-plus-version projections; every other drift remains rejected. Any
necessary ForceNew change needs its own reviewed, resource-specific
no-data-loss rollout and an explicit narrow contract change; do not disable the
destructive gate to make a routine PR pass.

The sandbox and production `main.tf` files are deliberately separate state
roots with byte-identical module wrappers. The foundation checker enforces that
parity so environment-specific module arguments cannot drift silently. The
cell-prefix precondition is also intentionally redundant with today's
constructed prefix: it preserves the authority boundary if a future refactor
accepts a prefix as input.

## Standing cost

This dark foundation still incurs standing AWS charges in both environments.
Each environment creates six Interface VPC endpoints in three Availability
Zones, plus one ElastiCache Serverless cache. The endpoints accrue endpoint
AZ-hour charges even with deny-all policies and zero ingress; ElastiCache
accrues its provider minimum and usage charges even before authority traffic
exists. KMS, CloudWatch Logs, DynamoDB, both ECR repositories, and Secrets
Manager may also incur
storage or request charges as their resources are used.

These resources are intentional prerequisites, not evidence that the runtime
is active. Record an environment-specific cost review immediately before each
first apply. If the standing cost is not accepted, do not apply the foundation;
do not weaken the private-only design by removing endpoints as a cost shortcut.

The OTP cache intentionally disables automatic snapshots. Challenges and rate
limits are short-lived and re-derivable, so recovery creates an empty cache
rather than restoring expired or consumed challenge state.

## Sandbox teardown

Both ECR repositories use `prevent_destroy` in sandbox as well as production so
immutable digest pins and rollback evidence cannot disappear during a routine
teardown. An intentional sandbox teardown requires a reviewed change removing
the relevant lifecycle guard, confirmation that no SSM digest pin or rollback
still references the images, and deletion through Terraform. Do not remove a
repository from state, which would orphan the protected publisher target.

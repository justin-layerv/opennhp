# qURL Connector Assigned-Cell Registration

## Status

The server composition remains dark when its atomic IaC bundle is null.
Sandbox Terraform now declares the complete `cell0` and `cell1` blue graphs;
the Control runtime and both refreshed cell fleets must still be applied and
live-proven before customer traffic. Production keeps the bundle validation-
locked to null. Operators must not enable the path by manually setting process
environment variables.

## Owned wire surface

When enabled, this composition exclusively owns these qURL Connector messages:

| NHP header | Claimed body | Result |
|------------|--------------|--------|
| `NHP_OTP` | Top-level `aspId=agent` | One-way OTP request; never emits an NHP response |
| `NHP_REG` | Top-level `aspId=agent` | Registration activation; may emit `NHP_RAK` |
| `NHP_LST` | Top-level `aspId=agent` and immediate `usrData.query=agent_registration_completion` | Post-RAK completion; may emit `NHP_LRT` |

The authenticated NHP header is the sole discriminator between OTP and
registration because their conservative body predicates intentionally match the
same `aspId=agent` umbrella. Enabling this composition therefore asserts that
there is no non-Connector `NHP_OTP` or `NHP_REG` flow using `aspId=agent`.
That inventory is an activation gate, not a runtime fallback: claimed malformed
or unknown forms go through the strict decoder and fail closed.

Only `IngressTransportDirectUDP` may reach Connector Authority. Relayed,
WebRTC, `Unknown`, and future ingress values are claimed and dropped before
Authority or generic plugin dispatch. Other ASPs and non-completion Agent LST
queries retain their existing dispatch until their separately staged retirement.

## Startup contract

The ten registration variables and three credential-recovery variables below
are one atomic, IaC-owned cell configuration. If both families are entirely
absent the feature stays dark. A partial family, only one family, or any empty,
malformed, or inconsistent value fails server startup before AWS client
creation or UDP bind.

The shared cell-target validator requires one common Terraform-selected
`:blue` or `:green` graph across all four operations. It rejects `:active`,
`$LATEST`, numeric versions, other named aliases, mixed colors, wrong
operations, wrong cells, and environment, account, or region drift before AWS
client creation or UDP bind. Startup loads one AWS identity only after the
complete graph passes, then gives registration a three-method client and
credential recovery a separate one-method client.

| Variable | Contract |
|----------|----------|
| `NHP_CONNECTOR_REGISTRATION_AWS_REGION` | AWS region containing the three cell Authority aliases |
| `NHP_CONNECTOR_REGISTRATION_AWS_ACCOUNT_ID` | AWS account containing those aliases |
| `NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN` | Exact `layerv-nhp-<environment>-ca-iro-<cell>:{blue\|green}` alias ARN |
| `NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN` | Exact `layerv-nhp-<environment>-ca-ar-<cell>:{blue\|green}` alias ARN |
| `NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN` | Exact `layerv-nhp-<environment>-ca-cr-<cell>:{blue\|green}` alias ARN |
| `NHP_CONNECTOR_REGISTRATION_AUTHORITY_LAMBDA_TIMEOUT` | Go duration; integer seconds and at least three seconds |
| `NHP_CONNECTOR_REGISTRATION_HANDLER_BUDGET` | Receipt-anchored handler budget |
| `NHP_CONNECTOR_REGISTRATION_PACKET_BUDGET` | Receipt-anchored total packet budget |
| `NHP_CONNECTOR_REGISTRATION_RESPONSE_RESERVE` | Validation-only response-tail bound |
| `NHP_CONNECTOR_REGISTRATION_WRITE_BUDGET` | Physical UDP write budget |
| `NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_REGION` | Must equal the registration AWS region |
| `NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_ACCOUNT_ID` | Must equal the registration AWS account |
| `NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN` | Exact same-color `layerv-nhp-<environment>-ca-ccr-<cell>:{blue\|green}` alias ARN |

`NHP_ENVIRONMENT` and `NHP_CELL_ID` are also validated and required explicitly
once any Authority variable above enables the composition, but they do not
participate in the all-or-none presence gate and cannot enable it themselves.
Environment must be `sandbox` or `prod`; the cell ID must be the canonical
lowercase cell identifier. The duration ladder is strict:

```text
authority Lambda timeout < handler budget < packet budget < transaction timeout
0 < write budget <= response reserve <= packet budget - handler budget
```

There are no runtime timing defaults.

The cell Terraform module validates the complete same-color alias inventory,
account, region, and the five-value sandbox measurement candidate before it
creates any reachability. It then renders these variables into the NHP server
environment, creates a private-DNS Lambda interface endpoint in that cell VPC,
and grants the cell server role `lambda:InvokeFunction` only for the four exact
aliases and only through that endpoint. The endpoint security group accepts
HTTPS only from the cell server security group. The native SDK still speaks
only UDP to its assigned NHP cell; the cell server has no NAT or public Lambda
API route for its internal Authority calls.

That invocation is AWS-service-mediated; it is not an IP route from a cell VPC
to the Control VPC where the Authority function ENIs run. Control and cell
security groups are VPC-local, and no peering, Transit Gateway, or route joins
the two VPCs. The original cell1 `10.102.0.0/16` therefore did not make Control
ENIs reachable or widen an SG source. It was still corrected in greenfield:
overlapping VPCs unnecessarily foreclose unambiguous future private routing.
Cell1 is pinned to the all-region-audited `10.104.0.0/16`, distinct from cell0
and its relay DMZ (`10.100.0.0/16` and `10.101.0.0/16`), Control
(`10.102.0.0/16`), and the UDP proof runner (`10.103.0.0/28`).

## Hub identity and discovery boundary

The Connector Hub has its own long-lived X25519 server identity; it does not
reuse a cell NHP-server identity. Its CREATE_ONLY seeder generates the private
key and active cookie key inside Lambda, persists only the exact
`private_key`/`active_cookie_key`/`previous_cookie_key` secret schema under the
Control data CMK, and publishes only the derived canonical public key to
`/<environment>/nhp/control/hub/identity/public-key`. No key byte or
version-specific identifier crosses the invocation response into Terraform
state.

The transaction is retry-safe rather than blindly one-shot. It validates and
reuses the exact `AWSCURRENT` private key after a partial invocation, accepts
the public parameter only when it is the initial `pending-keygen` sentinel or
already equals the derived key, and fails on any third value. The worker service
depends on that transaction, so tasks cannot start with an empty secret or an
unpublished public identity. KMS use is constrained to Secrets Manager and that
exact secret encryption context.

This SSM output is an internal publication boundary, not the native-client
discovery contract. A separate manifest/assignment producer must read it and
publish the Hub UDP endpoint plus public identity through the signed bootstrap
artifact; the Hub image publisher must not gain that role. Native Connector
traffic remains UDP-only throughout.

For the qURL CLI, the signed bootstrap artifact is the official binary release.
The production rollout reads the public SSM value, commits the SHA-256 of its
decoded 32-byte key in qurl-integrations, and sets the matching public repository
variable. That repository's release workflow verifies the value with the CLI's
runtime X25519 decoder before injecting it into GoReleaser, and its signed
checksum manifest binds the resulting binary. The release job receives no NHP
production role, and the cell server key is never an acceptable substitute for
this independent Hub identity.

## Provisioned-cell service topology

A provisioned cell is the NHP-server cluster and its cell-local qurl-service
cluster together. The current greenfield sandbox has a real cell1 NHP surface
but no cell1 qurl-service ECS service. Therefore the lean cell1 root and this
Authority/Hub substrate cannot, by themselves, satisfy the two-cell proof.

Before the `cell1` caller graph or eight-image proof manifest is enabled, a
separate narrowly reviewed topology PR must deploy a real qurl-service service
on cell1's private subnets with its own task/execution IAM, secret/KMS access,
service discovery, logs, alarms, and immutable deployed digest output. The
`qurl_service_cell1` manifest value must come from that deployed cell1 service;
it must never be copied from cell0 or inferred from an ECR tag. Keeping this
topology change separate preserves a reviewable Authority/Hub rollback unit,
but it is a hard dependency, not deferred optional work.

## Activation and observability gates

Authority outcome and UDP delivery are separate signals. In particular,
`ConnectorRegistrationAuthoritySuccess` does not imply
`ConnectorRegistrationResponseSent`; response deadline, encryption, transaction
handoff, write, and short-write failures have distinct counters.

The Terraform activation PR and its rollout-ledger entry must, before customer
traffic:

1. provision one common selected `:blue` or `:green` four-operation graph and
   restrict the cell server role and its private Lambda endpoint to those four
   exact aliases, while retaining the separate three-method registration and
   one-method recovery clients inside the process;
2. dashboard request, Authority outcome, and response-delivery counters;
3. alarm at minimum on `ConnectorRegistrationIngressRejected`,
   `ConnectorRegistrationInvokeFailed`,
   `ConnectorRegistrationResponseDeadline`,
   `ConnectorRegistrationResponseEncodeFailed`,
   `ConnectorRegistrationResponseHandoffFailed`,
   `ConnectorRegistrationResponseWriteFailed`,
   `ConnectorRegistrationResponseShortWrite`, and
   `ConnectorRegistrationInternalFailure`;
4. prove each provisioned sandbox cell has both a healthy NHP-server cluster
   and its own healthy qurl-service cluster, then prove direct UDP
   OTP/REG/RAK/completion end to end in each cell, including non-direct
   rejection and deadline failure;
5. retain the composition dark if any gate is missing or unhealthy.

The fixed counter definitions in
`endpoints/server/connector_registration.go` are the canonical metric-name
surface; no attacker-controlled value is used as a metric name or dimension.

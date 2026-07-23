# qURL Connector Assigned-Cell Registration

## Status

The server composition is dark by default. Terraform, IAM, dashboards, alarms,
and sandbox proof must land before an environment enables it. Operators must
not enable the path by manually setting process environment variables.

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
4. prove direct UDP OTP/REG/RAK/completion end to end in every provisioned
   sandbox cell, including non-direct rejection and deadline failure;
5. retain the composition dark if any gate is missing or unhealthy.

The fixed counter definitions in
`endpoints/server/connector_registration.go` are the canonical metric-name
surface; no attacker-controlled value is used as a metric name or dimension.

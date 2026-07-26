# runtime-attestation-store

Immutable per-node runtime evidence for the sandbox UDP-proof deployment
manifest.

Launch-template, SSM tag, AMI, or ECR lookups cannot prove what each current
in-service instance is actually running: NHP servers run a Docker container, and
`qurl-reverse-tunnel-server` pulls an ECR image only to extract a host binary and
then removes the container. This module provisions the evidence channel that
closes that gap, and publishes the two parameters the read-only producer
(`.github/scripts/collect_udp_proof_deployment_evidence.py`) requires:

| Parameter | Contents |
| --- | --- |
| `/sandbox/nhp/udp-proof/runtime-attestation-bucket-arn` | Exact bucket ARN |
| `/sandbox/nhp/udp-proof/runtime-attestation-collector-contract` | Canonical collector, unit, repair-document, and bucket-policy digests |

## Why not SSM custom Inventory

`ssm:PutInventory` is not resource-scoped. A single compromised instance role
could forge another instance's row, which would make the whole manifest
worthless. This store is resource-scoped by construction instead.

## The self-bound prefix

Each node role holds exactly one grant — `s3:PutObject` beneath
`runtime/${aws:userid}/` — and nothing else. For an EC2 role AWS substitutes
`aws:userid` with `<role-id>:<instance-id>`, so the prefix is self-bound: an
instance cannot name, let alone overwrite, another instance's object. Nodes
receive no list, read, delete, or overwrite-by-shared-prefix authority, and are
explicitly denied `kms:Decrypt`.

That grant lives in the **bucket policy**, not in identity policies, because the
bucket policy is the artifact the producer digests: it re-reads the live policy,
canonicalizes it, and fails closed on any drift from
`collector_contract.bucket_policy_sha256`.

## Bucket controls the producer re-verifies live

Versioning enabled · `BucketOwnerEnforced` · all four public-access blocks ·
SSE-KMS with the dedicated CMK and an S3 Bucket Key · a non-public bucket policy.

## The collector

One canonical, root-owned collector (`assets/collect-runtime-attestation.py`)
publishes `runtime/<aws:userid>/latest.json` after binding the exact instance,
role, ASG, launch-template, and boot identity to the live runtime artifact —
the running NHP container's ECR digest and `org.opencontainers.image.revision`
label, or the installed qRTS binary's SHA-256 and its boot-captured ECR build
receipt.

Installation is not user-data's job to get right: the pinned State Manager
document `layerv-nhp-sandbox-runtime-attestation-repair` writes the collector and
both systemd units only from payloads whose SHA-256 equals the published
contract, then enables the timer. A root-owned systemd timer publishes every five
minutes; State Manager's 30-minute association repairs and re-verifies the bytes
but is deliberately **not** the freshness clock — the producer rejects any object
older than ten minutes.

## Canonical JSON

The collector contract and the bucket policy are compared byte for byte against
the producer's canonical encoder (sorted keys, `,`/`:` separators, ASCII).
Terraform's `jsonencode` matches it exactly except that Go escapes `<`, `>`, and
`&`; preconditions in `storage.tf` and `parameters.tf` fail closed if any such
character ever enters either document.

## After applying

Feed `bucket_arn` and `kms_key_arn` into the `sandbox-udp-proof-runner` root's
`runtime_attestation_bucket_arn` / `runtime_attestation_kms_key_arn` so the
producer role gains its read-only S3/KMS grants.

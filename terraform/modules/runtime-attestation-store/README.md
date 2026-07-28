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

Launch-template identity comes from two independent control-plane records read
over SigV4 — the Auto Scaling membership row (`DescribeAutoScalingInstances`)
and the reserved `aws:ec2launchtemplate:*` tags EC2 stamps at launch — which
must agree. `DescribeInstances` returns **no** top-level `LaunchTemplate` for an
ASG-launched instance, and IMDS is deliberately not used for this field: it
serves the same tags over unauthenticated plaintext HTTP on a link-local
address, so one on-box redirect would let a node name whatever template it
liked. Both records state what the instance was *launched with*, so neither
drifts to the group's newer desired version during a rolling replacement.

Installation is not user-data's job to get right: the pinned State Manager
document `layerv-nhp-sandbox-runtime-attestation-repair` writes the collector and
both systemd units only from payloads whose SHA-256 equals the published
contract, then enables the timer. A root-owned systemd timer publishes every five
minutes; State Manager's 30-minute association repairs and re-verifies the bytes
but is deliberately **not** the freshness clock — the producer rejects any object
older than ten minutes.

## The qRTS boot capture

`qurl-reverse-tunnel-server` keeps no container: its user-data pulls the ECR
image, `docker cp`s the binary out, and `docker rmi`s the image. The ECR digest
and OCI revision are therefore observable **only** during that window, so
`modules/qurl-reverse-tunnel-server/user_data.sh.tpl` writes
`/var/lib/layerv/runtime-attestation/boot-capture.json` before the `docker rmi`.
The collector refuses to publish without it.

The capture's `build_receipt_sha256` is not copied from anywhere — the node
reconstructs the canonical build receipt the publisher signs (a fixed-layout
ASCII line over `schema_version`, `source_revision`, `binary_path`,
`binary_sha256`) from its own observations. It can only match when the binary on
that disk is byte-identical to the signed one, and the producer re-derives the
same value from the cosign-verified attestation. Nothing is written on the two
legacy `docker cp` paths or on the S3 binary fallback: those have no ECR
provenance, and the right output is no capture at all.

## The association must not go green while the fleet publishes nothing

The repair step runs `layerv-collect-runtime-attestation.py --verify`
synchronously and lets the exit status stand, so State Manager compliance —
`CRITICAL`, `max_errors = 0` — is where a broken evidence channel surfaces.
Before that, the step's only exercise of the collector was `systemctl start
--no-block ... || true` followed by an unconditional success line, and all three
frps instances reported `Success` for eleven hours while the collector failed
every run and the store held no frps object.

`--verify` performs every observation an attestation is made of and publishes
nothing. It skips two things on purpose:

- **the collector's own repair-status check**, which is self-referential and
  would latch the association red forever after one failure (a failed execution
  makes every later collector run fail, which fails the next execution);
- **the upload**, because the store holds exactly one object per instance and
  the producer requires it to be unique and current — a probe object would
  either break that or overwrite real evidence.

It exits 0 on an instance that is not `InService`: tag-targeted runs also reach
Pending, Standby, and Terminating members that the producer never reads, and
failing the association for one would take the fleet's evidence channel down
during any rolling replacement.

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

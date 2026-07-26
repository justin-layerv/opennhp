# 2026-07-25 · Issue #3227 · UDP proof deployment-manifest producer

- **Owner:** UDP proof rollout coordinator
- **Source:** [issue #3227](https://github.com/layervai/nhp/issues/3227) · rollout plan `prancy-mapping-wilkinson`

Enable the trusted-main, read-only sandbox producer only after every runtime
identity source exists. The workflow must fail closed until this list is
complete; it never accepts operator-supplied hosts, keys, SHAs, image digests,
or topology.

- [ ] Pre-rollout — runtime identities: apply the Hub public-key parameter
      producer, apply the cell1 qurl-service runtime contract from NHP #3461,
      and land the separate NHP cell0 runtime-contract publisher/IAM
      foundation. Land the trusted-main qurl-service publisher that signs an
      OCI attestation binding each deployed digest to its full `main` source
      revision. Converge Hub/cell0/cell1/qurl-service/Authority/qRTS runtime
      workloads, and activate cell1 only through the catalog's existing
      two-cell readiness gate.
- [ ] Pre-rollout — immutable node evidence: provision the versioned,
      bucket-owner-enforced, public-blocked sandbox attestation bucket and its
      dedicated CMK; set this root's exact `runtime_attestation_bucket_arn` and
      `runtime_attestation_kms_key_arn`; install the bounded collector/repair
      association on every cell0, cell1, and qRTS instance. Publish the
      canonical collector contract at
      `/sandbox/nhp/udp-proof/runtime-attestation-collector-contract`, binding
      the collector, service/timer units, exact repair document version/content
      digest, and canonical bucket-policy digest. The repair association must
      target each exact ASG. qRTS publication must keyless-sign the exact image
      digest and publish the canonical runtime build receipt as a raw-URI
      cosign attestation of type
      `https://layerv.ai/attestations/qurl-reverse-tunnel-server-build-receipt/v1`.
      The producer must verify the exact trusted-main workflow identity,
      workflow SHA, repository, one exact ECR subject/digest, and canonical
      receipt before accepting it. Its qRTS host evidence must independently
      hash the installed binary and canonical receipt bytes, and both hashes
      must equal the identity-bound receipt attestation for the digest actually
      running on the fleet.
- [ ] Pre-rollout — Connector canary: land the final reviewed private-FRP
      dependency pin in the trusted Connector canary workflow and produce one
      successful signed/attested trusted-main canary for the current Connector
      and qurl-go PR heads.
- [ ] Rollout — GitHub trust: create protected environment
      `udp-proof-manifest-sandbox`, restrict deployment branches to `main`, and
      store only a dedicated GitHub App's ID/private key. Install that App on
      exactly the eleven repositories listed in the producer workflow with
      read-only Actions, Attestations, Contents, Packages, and Pull requests
      permissions.
- [ ] Rollout — AWS trust: apply the standalone sandbox UDP-proof-runner root,
      read back `manifest_producer_role_arn`, and confirm its OIDC subject is
      exactly `repo:layervai/nhp:environment:udp-proof-manifest-sandbox`. Do not
      add runtime-attestation S3/KMS access until both exact ARNs are configured.
- [ ] Post-rollout: dispatch the workflow from the current signed `main`, prove
      it uploads one `udp-proof-deployment-manifest-<run_id>-<run_attempt>`
      artifact containing exactly the three canonical JSON files, and record
      the successful run plus artifact digest on issue #3227.
- [ ] Rollback: remove the environment's App credentials to stop new
      production immediately; preserve existing artifacts for investigation.
      If the AWS reader is no longer needed, remove its role in a reviewed
      standalone-root apply.

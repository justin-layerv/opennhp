# Deploy sandbox cell1 qurl-service

This runbook creates and proves the private qurl-service data plane in
`sandbox-cell1`. It does not publish cell1 in the assignment catalog and does
not add a public HTTP endpoint. The service must run one healthy task while it
is dark so activation is a routing decision, not the first runtime test.

## Preconditions

1. Merge and apply [NHP #3459](https://github.com/layervai/nhp/pull/3459)
   first. That CIDR relocation is the network foundation for this root; do not
   plan or apply the cell1 service against the superseded address layout.
2. Land and apply the separately reviewed cell0 publisher foundation. It must
   create `/sandbox/nhp/qurl-service/runtime-contract` and the exact main-ref
   role `layerv-nhp-sandbox-cell0-qurl-service-publisher`. That role is the
   only workflow principal allowed to publish the shared
   `layerv/nhp-qurl` image and may otherwise read that repository, update only
   the cell0 record, register only the cell0 task-definition family, update
   only the cell0 ECS service, and pass only its task/execution roles. The
   record uses the same exact three-key schema as cell1:

   ```json
   {"image_uri":"767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@sha256:<64-lowercase-hex>","schema_version":1,"source_revision":"<40-lowercase-hex>"}
   ```

   This cell1 PR does not create the cell0 record or role. The current short
   cell0 image tag is not source evidence, and a missing OCI revision label
   cannot be repaired by guessing a commit. Do not broaden an existing ECR
   publisher or the cell1 role to stand in for this exact cell0 foundation.
3. Apply the sandbox-cell1 root with `deploy_qurl_service = false`. This creates
   the exact publisher role and
   `/sandbox-cell1/nhp/qurl-service/runtime-contract`; its initial
   `UNPUBLISHED` sentinel deliberately cannot pass the deployment checks.
4. Land a dedicated qurl-service publisher at
   `.github/workflows/publish-cell-runtime.yml`. AWS cannot evaluate GitHub's
   `workflow_ref` claim, so the role trust binds
   `repo:layervai/qurl-service:ref:refs/heads/main` and the workflow must fail
   before requesting AWS credentials unless all of these are exact:
   `github.repository == layervai/qurl-service`,
   `github.ref == refs/heads/main`, and
   `github.workflow_ref ==
   layervai/qurl-service/.github/workflows/publish-cell-runtime.yml@refs/heads/main`.
   Do not reuse a PR job or environment subject.
5. The workflow must build from the full `GITHUB_SHA`, set the OCI
   `org.opencontainers.image.revision` label to that full 40-hex SHA and scan
   the local image before requesting AWS credentials. Under the exact cell0
   publisher role, a new digest is pushed only under a deterministic
   workflow-attempt staging tag. Pull and scan that exact served
   `repository@sha256` image, create and verify its trusted-main build
   provenance, and only then promote the staged manifest to the canonical
   full-SHA tag and read that tag back. An existing canonical full-SHA tag is
   reusable only after its exact digest's trusted-main attestation verifies.
   Cancellation before promotion must leave no new unproven canonical
   candidate. The cell1 publisher role deliberately has no ECR write grant.
   After canonical promotion or verified reuse, each cell leg independently
   resolves the registry digest from that exact tag and verifies the OCI source
   label again from the digest-addressed image using its exact-repository read
   grant.
6. Only after those checks, construct the record with a deterministic JSON
   encoder (sorted keys, compact separators):

   ```json
   {"image_uri":"767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@sha256:<64-lowercase-hex>","schema_version":1,"source_revision":"<40-lowercase-hex>"}
   ```

   Publication is atomic per cell, not across both cells. In `publish_only`,
   write and immediately read back cell0, then do the same for cell1, without
   querying or mutating ECS. In `publish_and_deploy`, process cell0 completely
   before cell1: verify the exact image and live target, deploy and prove that
   cell's ECS service, and only then write and read back that cell's record.
   If deployment or publication fails after an ECS update, automatically
   restore the prior task definition and prove the rollback task fleet. If a
   contract write was attempted, only after proving ECS rollback restore and
   read back the prior SSM contract. A failed ECS or SSM compensation,
   interruption, or cell0-success/cell1-failure result is deliberately
   fail-closed: do not generate manifest proof until the same reviewed
   trusted-main workflow is rerun and both cells converge. Never copy or infer
   the cell0 source from its current short task-definition tag or digest. The
   cell1 Terraform root rejects extra keys, non-canonical JSON, a missing
   image, or a digest that does not retain the exact full-SHA tag. Each role
   remains scoped to its own record and runtime.
7. The publisher workflow's `publish_and_deploy` cell1 leg must register only
   the cell1 task-definition family and update only the cell1 ECS service. The
   current [ECS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerservice.html)
   supports task-definition resource scoping, so both `RegisterTaskDefinition`
   and its create-only `TagResource` authorization use the exact cell1 family
   ARN. The request also requires a present,
   all-values-Fargate compatibility set, non-privileged containers, exact CPU
   and memory, exact PassRole, and exact UpdateService constraints.
   Registration must preserve the root's standard tags and include
   exactly the IAM-declared key set: `Organization=LayerV`,
   `CostCenter=infrastructure`, `Owner=platform-team`, `Project=NHP`,
   `Application=nhp`, `Environment=sandbox-cell1`,
   `Repository=layervai/nhp`, `Cell=cell1`, `Service=qurl`,
   `Name=layerv-nhp-sandbox-cell1-qurl-api`,
   `Component=qurl-service`, `LayerVCell=cell1`,
   `ManagedBy=qurl-service-publisher`,
   `SourceRepository=layervai/qurl-service`, and
   `SourceRevision=<full SHA>`. It may pass only the cell1 task and execution
   roles. Its `ecs:TagResource` grant is valid only during
   `RegisterTaskDefinition`; it cannot retag an existing resource.

The NHP PR remains apply-blocked until the CIDR relocation is applied, both
record foundations exist, and the producer contract in steps 4-6 is live. The
Terraform root intentionally has no fallback to the legacy cell0 tag.

## Publisher phases

The reviewed workflow accepts exactly two operator inputs: the required
`phase` choice and a required `confirmation` string. It accepts no
operator-supplied image tag, digest, source revision, record JSON, cell,
cluster, service, task-definition, role, repository, registry, or parameter
path. Those values come from the reviewed workflow, `GITHUB_SHA`, live
read-back, and the fixed cell contracts above.

- For initial foundation, choose `publish_only` and enter exactly:

  ```text
  PUBLISH BOTH CELL RUNTIME CONTRACTS
  ```

  This phase builds and proves the image, then writes and reads back cell0
  followed by cell1. It does not query, register, or update ECS. The cell1 ECS
  cluster/service does not exist yet; absence is expected and cannot make this
  phase retry deployment. A new image becomes canonical only after its staged
  digest passes served-image scanning and exact trusted-main attestation
  verification; verified existing canonical tags remain reusable. A published
  record is desired provenance, not proof that either live service already
  runs it.
- After `publish_only` succeeds, perform the attended Terraform enable/apply
  below. Terraform creates the initial cell1 service directly from the proven
  record at desired count one.
- Only after both ECS services exist and are healthy, choose
  `publish_and_deploy` and enter exactly:

  ```text
  PUBLISH AND DEPLOY BOTH CELL RUNTIMES
  ```

  This phase processes cell0 and then cell1. For each cell it re-verifies the
  full-SHA tag, exact digest, and OCI source label; reads and validates the live
  task definition; rejects family, `awsvpc`, Fargate, CPU, memory, or privileged
  drift; changes only the `qurl-api` image; registers and deploys the constrained
  revision; waits for service stability; and proves every running task reports
  the new task-definition ARN, image URI, and digest. Only after that live proof
  does it advance and read back the cell's SSM record.

The workflow is serialized with `cancel-in-progress: false`; do not manually
cancel it during a rollout. On a deployment/publication error after service
mutation it restores the prior task definition and proves the rollback task
fleet. If contract publication was attempted, it then restores and reads back
the prior SSM contract. Any failed ECS or SSM compensation, external
interruption, or cross-cell partial result blocks multi-image manifest proof
until a rerun converges both cells on the same reviewed source.

## Enable and apply

1. Change only `deploy_qurl_service = true` in
   `terraform/environments/sandbox-cell1/terraform.tfvars`.
2. Run a reviewed saved plan for the sandbox-cell1 root. Confirm it creates:
   cell1 qURL tables, two cell-local secrets, the ECS cluster/service/task
   definition, an internal ALB in private subnets, one private Route 53 alias,
   the exact execution-role boundary, log group, and healthy-target alarm.
3. Reject the plan if it creates an internet-facing ALB, a public Route 53
   record, any `0.0.0.0/0` qurl-service ingress, a cell0 resource mutation, or
   any assignment/catalog activation.
4. Apply the saved plan. The service desired count is exactly one; do not
   reduce it to zero to represent “dark.”

## Runtime proof before activation

Record the following in the multi-image proof manifest:

- Byte-exact read-backs of both `/sandbox/nhp/qurl-service/runtime-contract`
  and `/sandbox-cell1/nhp/qurl-service/runtime-contract`; both must name the
  proven digest/full-source pair and neither may be inferred from a short tag.
- `qurl_service_runtime_image_uri` and
  `qurl_service_runtime_source_revision` from Terraform output.
- The live ECS service task-definition ARN and its `qurl-api` container image.
  The image must exactly equal the output `repository@sha256` value.
- `QURL_RUNTIME_SOURCE_REVISION` from that same live task definition. It must
  equal the 40-hex output and the digest's OCI revision label.
- ECS `desiredCount=1`, `runningCount=1`, rollout state `COMPLETED`, and one
  running task on that exact task-definition revision.
- Every target in `qurl_service_target_group_arn` is `healthy`, and the
  `*-qurl-api-no-healthy-targets` alarm reaches `OK`.
- The ALB scheme is `internal`; its security group admits TCP/80 only from the
  cell1 NHP server security group. ECS task ingress admits the application port
  only from the ALB security group. ALB egress is that same application port
  to the exact ECS SG; task DNS egress is TCP/UDP 53 only to the VPC resolver
  `/32`; task NHP egress is TCP/8888 only to the exact server SG.
- `qurl-api.<cell1 private Cloud Map namespace>` resolves to the internal ALB
  from the cell1 VPC and has no public hosted-zone record.
- CloudWatch receives fresh qurl-api log events from the proven task.
- The assignment/catalog source still has no active cell1 entry. Healthy
  private infrastructure is not authorization to route users to it.

Do not activate cell1 until every check is true. A healthy ECS task without
matching immutable image/source evidence is a failed proof.

## Rollback while dark

Before any catalog activation, set `deploy_qurl_service = false`, review the
destructive saved plan, and apply it. This removes the greenfield private data
plane and cell-local qURL tables/secrets while leaving the NHP UDP cell and the
publisher sentinel in place. After any future activation, first remove cell1
from assignment and wait for leases to drain; this pre-activation rollback is
not safe once customer state exists.

# UDP proof runner foundation

This sandbox-only module is the NHP-owned compute boundary for the attended,
deployed qurl-go and qURL Connector UDP proof. It deliberately provisions no
standing GitHub runner and implements no proof scenario or protocol fault. A
later NHP workflow composes this module. For each separately approved client
proof, it generates one organization-scoped GitHub JIT configuration and
dispatches the exact client harness against signed revisions and deployed
digests.

NHP owns this boundary because it owns the sandbox Hub/cell topology, the
allowlisted public UDP edges, and the eventual uniquely tagged assignment,
expiry, reassignment, revocation, and counter controls. qurl-go and Connector
remain proof consumers; neither should grow an AWS runner control plane.

## Security and lifecycle contract

- A dedicated, unpeered `/28` has one subnet, no inbound security-group rule,
  and egress only for its VPC resolver, HTTPS, Amazon Time Sync, and NHP UDP
  62206. There is no route to a cell or Control VPC other than the public edge.
  NHP UDP egress intentionally remains `0.0.0.0/0`: assignment returns a
  LayerV-owned DNS name whose public NLB address set may rotate, while the
  client authenticates the responding server against the assigned public key.
  Freezing current NLB `/32`s into this security group would defeat that DNS
  indirection without containing the already accepted root-capable proof job,
  which also needs broad HTTPS egress.
- One persistent EIP is the stable source `/32` reviewed in sandbox Hub and
  cell ingress. The serialized broker preflights the tagged fleet, launches one
  exact template, and attaches that EIP with reassociation forbidden. A second
  instance cannot steal the source address; any attach error terminates the new
  instance, and the sweeper terminates every runner if it ever observes an
  ambiguous multi-instance fleet.
- The launch template has no SSH key or inbound path. It requires IMDSv2 with
  response hop limit `2`, encrypted/delete-on-termination storage, and
  `instance_initiated_shutdown_behavior=terminate`. The two-hop response is
  required for the hardened Connector container to obtain the runner role's
  short-lived KMS credentials across Docker's bridge. It does not establish a
  separate trust boundary: the exact attended proof job is already root-capable
  on this disposable host, and unrelated or unreviewed workflows remain
  forbidden from targeting the runner.
- Bootstrap installs Docker, `iproute2`/`tc`, iptables, and tcpdump. Packet
  capture receives only `CAP_NET_ADMIN`/`CAP_NET_RAW`; latency/loss simulation
  runs inside an explicitly `--cap-add=NET_ADMIN` disposable container. The
  host qdisc is not changed by bootstrap. Docker-group membership makes the
  exact attended proof job root-capable on this disposable host; containers
  provide reproducibility and fault namespaces, not a security boundary, so no
  unrelated or unreviewed workflow may target the runner. Ubuntu's default APT
  sources are upgraded to HTTPS before refresh so no TCP 80 egress is needed.
- The runner uses a checksum-pinned official `actions/runner` linux-x64
  archive and a one-use JIT configuration. The JIT value is held in one
  KMS-encrypted, run-and-attempt-tagged secret, read once, force-deleted before
  repository code runs, and never written to logs or user data. The Actions
  runner CLI necessarily receives the one-use JIT value in its process argv,
  where the already-trusted `runner` user and root can observe it for the
  process lifetime. That bounded same-host exposure is accepted; it must not be
  copied into another process, artifact, or log.
- The EC2 role can read only the sandbox JIT-secret prefix with the module's
  environment/purpose tags. Dynamic run IDs cannot narrow its static IAM
  policy, so per-run ownership is operationally bounded by the single active
  runner and serialized broker; the one-use secret is deleted before job code.
  Its proof KMS surface is exact-key `DescribeKey`/`Decrypt`; decrypt
  additionally requires Connector's `qurl-agent-x25519-private-key` encryption
  context and an `aws-kms` or `aws-nitro` provider. It cannot list or read
  application secrets. This is a consciously accepted sandbox trust decision:
  any code in the attended job, including a compromised client transitive
  dependency, can use IMDS credentials to decrypt that sandbox Connector key
  and can exfiltrate it over HTTPS. Exact reviewed workflow SHAs, attended
  dispatch, one-use compute, and sandbox-only keys are therefore load-bearing;
  the role name does not create an in-host least-privilege boundary.
- The GitHub OIDC controller is trusted only for
  `repo:layervai/nhp:environment:udp-proof-sandbox`. It cannot call EC2 or read
  secrets. It may create tagged JIT metadata and invoke one broker Lambda.
  Creating a secret with the dedicated customer-managed JIT key requires the
  exact `GenerateDataKey`/`Decrypt` pair; both actions are restricted to that
  key through Secrets Manager, and the controller has no `GetSecretValue`
  permission with which to turn its service-bound decrypt grant into a secret
  read path.
- The distinct deployment-manifest producer is trusted only for
  `repo:layervai/nhp:environment:udp-proof-manifest-sandbox`. It is read-only:
  exact public SSM parameters, catalog rows, runtime images/functions/tasks,
  fleet identity, public DNS, and immutable versioned attestations. Its S3/KMS
  statement does not exist until the composing root pins both exact storage
  ARNs; it never shares the runner controller's mutation permissions.
- The serialized broker starts the exact Terraform-owned launch-template
  version. The workflow cannot override user data, the instance profile, AMI,
  instance type, storage, or network interface. AWS's
  [`ec2:IsLaunchTemplateResource`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html)
  condition is retained as defense in depth around the fixed broker code.
- Four cleanup paths converge: JIT runner exit, the instance's boot-anchored
  systemd deadline, the workflow's `always()` stop invocation, and an
  independent five-minute broker sweep. A wrong-template, wrong-source-EIP,
  stopped, expired, or concurrent module-tagged fleet fails closed; the sweeper
  terminates every ambiguous runner instead of choosing proof evidence from
  one. If launch fails before the runner consumes its JIT configuration, the
  encrypted secret remains unreadable without the runner role and the sweep
  deletes it after the bounded maximum-runtime cutoff.
- The broker attaches the dedicated EIP after launch and before returning
  success; the instance has no public egress until that association lands. The
  bootstrap retries its first network operations across this short window.
  Both start and sweep fail closed if the association is absent, unreadable, or
  still held by a prior runner. A run that collides with the prior instance's
  `shutting-down` window must wait for termination and use a fresh GitHub run
  attempt; the broker never reassigns the EIP from a live owner.

The protected GitHub environment needs deployment-branch restrictions and
attended approval before the controller role is applied. AWS also recommends
environment protection rules when an OIDC trust uses an environment subject:
<https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>.

## Composition contract

This foundation is intentionally inert until a sandbox root instantiates it.
The composing PR must:

1. Pin an x86_64 Ubuntu AMI ID, official runner archive URL and SHA-256, the
   dedicated non-overlapping `/28`, and only the exact current-account/current-
   region sandbox CMKs needed by the sealed-state proof. The module resolves the
   exact AMI ID and rejects any architecture other than `x86_64` before launch.
2. Apply the module and record `stable_source_cidr`; add that exact `/32` to
   the sandbox Hub and both cell public UDP ingress policies in the same saved
   plan. Do not allowlist GitHub-hosted runner ranges or a cloud CIDR.
3. Create and protect the NHP `udp-proof-sandbox` GitHub environment with
   deployment-branch restrictions and attended approval. Keep
   `controller_role_arn` in NHP repository configuration and the JIT GitHub App
   credentials only in that protected environment. NHP remains the sole
   OIDC/AWS controller; neither client repository receives the controller role,
   EC2 permissions, or broker credentials.
   Separately create `udp-proof-manifest-sandbox`, restrict it to NHP `main`,
   and store only the dedicated read-only manifest GitHub App credentials
   there. That App is installed on the producer's exact repository set with
   Actions, Attestations, Contents, Packages, and Pull requests read
   permissions; it has no write permission and is not reused as the JIT App.
4. Create a dedicated `udp-proof-sandbox` organization runner group with
   `visibility=selected` and repository access restricted to exactly private
   `layervai/qurl-connector` plus public `layervai/qurl-go`. Because qurl-go is
   public, `allows_public_repositories=true` is unavoidable; bind and read back
   that value explicitly rather than treating the selected-repository list as
   the public-repository boundary. The NHP repository must not be granted
   runner-group access: its controller stays on a GitHub-hosted runner while
   the client proof job consumes the stable-EIP host. The load-bearing public
   repository fence is `restricted_to_workflows=true` with
   `selected_workflows` set only to
   `layervai/qurl-connector/.github/workflows/sandbox-smoke.yml@<exact signed Connector candidate commit>`
   and
   `layervai/qurl-go/.github/workflows/native-udp-sandbox.yml@<exact signed qurl-go candidate commit>`.
   These are contract placeholders, not literal GitHub configuration. The
   later controller/composition PR pins those three values only after both
   clients reach their final reviewed proof heads: the exact Connector workflow
   commit, the exact qurl-go workflow commit, and the immutable Connector
   candidate digest from the trusted-main canary workflow. Keep each workflow
   identity separate from the Connector image under proof; a newer workflow
   head never authorizes a different image digest, and vice versa.
   A branch, tag, `@main`, reusable wrapper, or path-only restriction is not an
   exact workflow identity. Fork, pull-request, and unreviewed jobs therefore
   cannot match this group; only each dispatch-only strict job at its pinned
   full SHA can. Pass this group ID when
   [generating every JIT configuration](https://docs.github.com/en/rest/actions/self-hosted-runners#create-configuration-for-a-just-in-time-runner-for-an-organization),
   and read back all four group controls before dispatch:
   `visibility=selected`, the exact two repository IDs,
   `allows_public_repositories=true`, and
   [`restricted_to_workflows=true` with both full-SHA workflow identities](https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/manage-runners/larger-runners/control-access).
   Fail before minting a JIT configuration or dispatching a client workflow if
   any read-back value differs; the attended proof must not repair group access.
5. Install the JIT GitHub App narrowly: organization self-hosted-runners write
   for the exact two-repository runner-group check, plus Actions dispatch/read.
   Each controller run mints its Actions token for only the selected
   `layervai/qurl-connector` or `layervai/qurl-go` repository; the second
   polling-only window requests Actions read while dispatch, final
   verification/cancellation fallback, and failure cancellation request
   Actions write. It needs no client contents write, no AWS permission, and no
   Actions permission in NHP. A PAT is forbidden.
6. Update the client workflows in their own reviewed PRs before composing this
   module. Each strict `workflow_dispatch` path must accept the required
   canonical `deployment_manifest_b64` and `deployment_runtime_inputs_b64`
   bytes plus the authenticated producer run ID, run attempt, head SHA,
   artifact ID, and artifact digest. The clients hash and echo those inputs in
   typed proof evidence; they never source the Hub trust root or candidate
   identity from mutable repository variables. Each path also requires
   `nhp_controller_run_id` and `nhp_controller_run_attempt`, validates them
   against the broker's respective
   `[1-9][0-9]{0,19}` and `[1-9][0-9]{0,9}` bounds, and derive
   `run-<id>-attempt-<attempt>` itself. A client must not accept a
   preconstructed `runner_label` input. Each strict path must also require
   `dispatch_correlation_id` and render its run name exactly as
   `UDP proof [corr:<value>]`; the controller uses that title together with the
   candidate branch and full SHA as its unique dispatch lookup envelope. It
   targets both the exact organization group and its derived label, and binds
   both controller inputs into the proof evidence. The Connector's advisory
   pull-request matrix stays on
   `ubuntu-latest` and must never target the protected group; its dispatch-only
   strict job runs the host and hardened-container assertions in one JIT job
   because a JIT runner accepts exactly one job. The qurl-go
   `direct UDP lifecycle` dispatch job moves from `ubuntu-latest` to the same
   exact group-plus-derived-label contract. Neither workflow may fall back to
   generic self-hosted labels.
7. Use two separate, attended NHP controller runs under one non-canceling
   workflow-level concurrency group:

   - Connector first. Mint a JIT configuration whose labels are exactly
     `required_jit_labels` plus
     `run-<NHP github_run_id>-attempt-<NHP github_run_attempt>`, write its
     one-use secret, start the broker, dispatch the exact Connector strict
     workflow with `nhp_controller_run_id` and
     `nhp_controller_run_attempt` copied from that NHP controller run, and
     accept evidence only after verifying the external repository, workflow
     ID/path, event, requested/full head SHA, run attempt, successful
     conclusion, both echoed controller inputs, and exact artifact contract.
     Record the resulting Connector workflow run ID. An `if: always()`
     finalizer stops the broker even when mint, dispatch, proof, or verification
     fails.
   - qurl-go second. Require the verified Connector workflow run ID as
     `connector_proof_run_id`. Mint a distinct JIT configuration and secret
     keyed by this second NHP run and attempt, start the broker, dispatch the
     exact qurl-go workflow with that NHP run's
     `nhp_controller_run_id`/`nhp_controller_run_attempt` pair and the Connector
     run ID, then perform the same external-run and artifact verification before
     accepting evidence. Its independent `if: always()` finalizer also stops
     the broker.

   One JIT runner handles one client workflow; do not try to reuse a consumed
   runner or one NHP run across both clients.
8. For each NHP controller run, create
   `<jit_secret_prefix><github_run_id>/<github_run_attempt>` using
   `jit_kms_key_arn` and the exact tags `Environment=sandbox`,
   `Purpose=udp-proof`, `GitHubRunId=<github_run_id>`, and
   `GitHubRunAttempt=<github_run_attempt>`. Including `github.run_attempt` keeps
   an attended GitHub re-run distinct from its already-terminated first attempt.
   Invoke the broker with the exact JSON object
   `{"action":"start","github_run_id":"<digits>","github_run_attempt":"<digits>"}`.
   The synchronous start response is pinned to exactly `action`,
   `instance_id`, and `status`; `instance_id` must be an EC2 instance id and
   `status` must be `launched` or `existing`. The stop response is pinned to
   exactly `action`, `instances`, `secret_deleted`, and `status`;
   `status=terminated` requires one or more unique EC2 instance ids, while
   `status=absent` requires an empty instance list, and `secret_deleted` is
   boolean in either case. Extra fields or status values fail the controller
   closed. A red stop-schema check is therefore not by itself proof that
   compute survived: verify the broker sweep and boot-relative hard deadline
   before classifying a runner as stranded.
   Use a synchronous invoke with bounded retries for `TooManyRequestsException`:
   the intentionally serialized broker can briefly throttle while its
   five-minute sweep is running, and an asynchronous start would not prove the
   runner is ready. A sustained `DescribeAddresses` failure makes the sweeper
   terminate an otherwise healthy runner because it can no longer certify the
   stable source. The composing runbook must classify that as an aborted proof
   and require a fresh attended controller run, never in-place continuation.
   Generic labels alone are not an isolation boundary.
9. Record both NHP controller run identities, both external client workflow run
   identities, the runner AMI, archive digest, launch-template version, EIP `/32`,
   instance IDs, and tool versions in the later redacted proof manifest. Never
   treat module tests, a skipped runner job, or a successful launch as a UDP
   scenario result. Restrict packet captures to UDP 62206 and use short-lived,
   encrypted artifact retention; do not capture IMDS, JIT, or HTTPS traffic.
10. If the foundation is retired, remove every Hub/cell ingress reference to
   `stable_source_cidr` before releasing the EIP and verify that ordering in the
   saved destroy plan. Never release an address while its `/32` remains
   allowlisted; a later AWS customer could receive that public address.

The composition PR creates concrete apply, GitHub-environment, and ingress
tasks, so it requires a prod-rollout-ledger entry (sandbox tasks only). This
module-foundation PR creates no root instance and therefore has no rollout task
of its own.

## Validation

From this directory:

```bash
terraform init -backend=false
terraform test
python3 -m unittest -v lambda/test_broker.py
```

The Terraform contract test freezes the no-ingress network, persistent EIP and
broker-only association, launch-template teardown/IMDS/storage settings,
bootstrap tooling, exact OIDC subject, controller/broker separation,
context-bound KMS decrypt, and independent sweep. The Python tests cover strict
command decoding, post-JIT-deletion same-run idempotence, cross-run rejection,
exact-template launch, stop, TTL/wrong-template cleanup, fail-closed
multi-instance cleanup, and bounded JIT metadata deletion.

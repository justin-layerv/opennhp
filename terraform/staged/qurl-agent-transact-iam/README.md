# qURL agent transaction IAM staging root

This production-only root breaks the rollout dependency cycle tracked in
[nhp#3279](https://github.com/layervai/nhp/issues/3279). The legacy production
root cannot currently isolate the qURL task-role grant from unrelated resource
moves, table changes, and fleet changes. This root therefore owns one temporary
inline policy in separate state.

Do not apply this root locally and do not use `terraform destroy`. Its only
apply path is the manual `qURL Agent Transaction IAM (prod)` workflow from `main`,
which accepts a saved plan containing exactly one create. Applying the policy
does not authorize deployment of the transactional qurl-service writer: the
separate effective-permission simulation in the production rollout ledger must
be recorded first.

The approval window is two days from plan creation and is enforced before the
protected apply downloads the saved plan. The artifact is retained for three
days only so approval near the boundary gets a clear expiry error instead of
racing garbage collection. If approval does not complete in time, re-dispatch
the workflow and review a fresh plan. Do not re-upload or reuse an expired plan
merely to avoid replanning.

The workflow shares the `promote-to-prod` concurrency group with ordinary
production promotion. A run awaiting protected-environment approval therefore
queues regular production promotions; approve promptly, or cancel it and
re-dispatch when the reviewer is ready.

If apply succeeds but the post-apply convergence check fails, assume the
policy may already be installed. Do not retry apply or re-dispatch the
create-only workflow. Stop, inspect the job log and live IAM/staging-state
ownership read-only, run a separately reviewed read-only convergence plan, and
record the evidence on nhp#1952 before continuing the rollout.

The PR classifier intentionally treats non-Markdown changes in this directory
as production-only Terraform inputs: they must not run the unrelated sandbox
legacy-root plan. Markdown remains documentation-only under the classifier's
existing `terraform/*.md` rule, including this README.

The permanent handoff must preserve the live policy without dual Terraform
ownership. After the legacy root is healthy, add an identical standalone
`aws_iam_role_policy` there, disable the staging create workflow, remove this
address from staging state without destroying AWS, and immediately import it
into the legacy root. Keep this configuration until the import and live policy
hash are verified so a failed import can restore staging ownership.

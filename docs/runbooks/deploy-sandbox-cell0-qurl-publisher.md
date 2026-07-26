# Deploy the sandbox cell0 qurl-service publisher foundation

This change creates the cell0 half of the governed two-cell qurl-service
publisher:

- `/sandbox/nhp/qurl-service/runtime-contract`
- `layerv-nhp-sandbox-cell0-qurl-service-publisher`

It does not publish an image, change the live qurl-service task definition, or
deploy cell1.

## Preconditions

1. Merge the reviewed NHP foundation PR.
2. Merge the governed qurl-service
   `.github/workflows/publish-cell-runtime.yml` workflow.
3. Confirm the live cell0 service is
   `layerv-nhp-sandbox-cell0-qurl-api` in the same-named ECS cluster, its task
   and execution roles retain their exact deterministic names, and its stable
   task shape is Fargate `512` CPU / `1024` MB.
4. Confirm no existing IAM role or SSM parameter has either target name. Do not
   import or overwrite an operator-created lookalike.
5. Bring the sandbox root to a reviewed no-op on the current merged baseline
   first. Do not use `-target` to hide an earlier unapplied controller,
   Authority, networking, or runtime-evidence mutation.

## Apply

1. Run a current authenticated Terraform 1.14.3 plan for
   `terraform/environments/sandbox`.
2. Save the plan and reject it unless the only foundation mutations are the
   new SSM String parameter, OIDC role, and inline policy plus the two output
   values. Unrelated live drift must be resolved separately.
3. Apply only that reviewed saved plan.
4. Read back the role trust and policy. The trust must name only
   `layervai/qurl-service` on `refs/heads/main`; the policy must name only the
   shared qurl-service ECR repository, the cell0 runtime contract, cell0 ECS
   family/service/tasks, and the two cell0 task roles.
5. Read back the SSM value byte-for-byte as
   `{"schema_version":1,"status":"UNPUBLISHED"}`.

Do not dispatch the publisher until the separate cell1 foundation exists. The
publisher intentionally promotes both cells in order and fails closed if
either exact contract/role is absent.

## Rollback

Before the first publisher run, a reviewed saved-plan rollback may remove the
three foundation resources. After publication, do not destroy the parameter or
role until both cell services have been taken out of the proof/deployment
chain and the current immutable contract has been retained as evidence.

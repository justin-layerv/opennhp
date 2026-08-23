# ECR Module
# Creates ECR repositories in primary account (sandbox) and replicates to secondary accounts (prod).
# With replication enabled, each account has its own copy of every image -- prod has no runtime
# dependency on sandbox ECR.
#
# ==================== GitHub Actions CI/CD Permissions ====================
#
# This module manages ALL GitHub Actions CI/CD IAM permissions, not just ECR.
# The GitHub Actions role created here is used by CI workflows for:
# - ECR push (container images)
# - Terraform state access (S3/DynamoDB)
# - Infrastructure deployment (EC2, ECS, CloudFront, S3, etc.)
# - QURL link static site (CloudFront, S3, ACM)
#
# This consolidation avoids circular dependencies between modules and keeps
# all CI/CD permissions in one place for easier auditing.
#
# ==================== Organization-Managed Resources ====================
#
# Some organizations manage certain IAM resources centrally via Service Control
# Policies (SCPs). This module supports both self-managed and org-managed scenarios:
#
# 1. OIDC Provider (GitHub Actions):
#    - Set `create_oidc_provider = false` if your organization manages the
#      GitHub OIDC provider centrally or if SCP blocks iam:CreateOpenIDConnectProvider
#    - When false, the module uses a data source to reference the existing provider
#
# 2. GitHub Actions IAM Role:
#    - Named `nhp-${environment}-github-actions` to support multiple environments
#    - Each environment gets its own role with appropriate permissions
#
# See terraform.tfvars for environment-specific settings.
# ============================================================================

# ==================== Variables ====================

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "github_org" {
  description = "GitHub organization"
  type        = string
  default     = "layervai"
}

variable "github_repo" {
  description = "GitHub repository"
  type        = string
  default     = "nhp"
}

variable "is_primary_account" {
  description = "Whether this is the primary account that owns ECR repositories"
  type        = bool
  default     = true
}

variable "primary_account_id" {
  description = "AWS account ID of the primary account (for cross-account ECR access)"
  type        = string
  default     = ""
}

variable "terraform_state_bucket" {
  description = "S3 bucket name for Terraform state (for GitHub Actions permissions)"
  type        = string
  default     = ""
}

variable "terraform_lock_table" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
  default     = "terraform-state-lock"
}

variable "secondary_account_ids" {
  description = "List of AWS account IDs that can pull from ECR (for cross-account access)"
  type        = list(string)
  default     = []
}

variable "enable_replication" {
  description = <<-EOT
    Enable ECR cross-account replication from primary to secondary accounts.

    When true (primary account only):
    - Creates an ECR replication configuration that copies all images under
      the 'layerv/' repository prefix to each secondary account.
    - Images are replicated automatically on push (one-time copy per tag).
    - Secondary accounts pull from their own local registry at runtime,
      eliminating any runtime dependency on the primary account.

    When true (secondary account only):
    - Creates an ECR registry policy that allows the primary account's
      replication service to write images into the local registry.
  EOT
  type        = bool
  default     = false

  # Catch the obvious misconfiguration "I'm the primary AND I'm pretending to
  # have a primary upstream" early. The replication code paths are
  # mutually exclusive between primary and secondary, and silently letting
  # both flags be set produces confusing apply-time errors much later.
  validation {
    condition     = !(var.enable_replication && var.is_primary_account && var.primary_account_id != "")
    error_message = "When enable_replication=true on the primary account, primary_account_id must be empty (a primary account does not have a primary upstream)."
  }
  validation {
    condition     = !(var.enable_replication && !var.is_primary_account && var.primary_account_id == "")
    error_message = "When enable_replication=true on a secondary account, primary_account_id is required (the registry policy must trust a specific primary account)."
  }
  validation {
    condition     = !(var.enable_replication && !var.is_primary_account && length(var.secondary_account_ids) > 0)
    error_message = "secondary_account_ids must be empty on a secondary account; it is only meaningful in the primary account that drives replication outbound."
  }
}

variable "traefik_plugins_github_repo" {
  description = "GitHub repository for traefik-plugins (e.g., 'traefik-plugins')"
  type        = string
  default     = "traefik-plugins"
}

variable "plugin_repos" {
  description = "List of GitHub repository names that can assume the GitHub Actions role to upload plugins"
  type        = list(string)
  default     = []
}

variable "plugin_bucket_arn" {
  description = "ARN of the S3 bucket for Traefik plugins (from AC module)"
  type        = string
  default     = ""
}

variable "enable_plugin_bucket_policy" {
  description = "Whether to create the plugin bucket write policy (set to true when AC module is deployed)"
  type        = bool
  default     = false
}

variable "environment" {
  description = "Environment name (sandbox, prod) - used to namespace IAM resources"
  type        = string
  default     = "sandbox"
}

variable "agent_otp_ses_enabled" {
  description = "Whether this environment provisions agent-registration SES resources and needs the matching Terraform apply grant"
  type        = bool
  default     = false
}

variable "create_oidc_provider" {
  description = <<-EOT
    Whether to create the GitHub OIDC provider.

    Set to `false` if:
    - Your organization manages the OIDC provider centrally
    - SCP blocks iam:CreateOpenIDConnectProvider
    - The provider already exists from another deployment

    When false, the module uses a data source to reference the existing provider.
  EOT
  type        = bool
  default     = true
}

variable "deploy_qurl_ecr" {
  description = "Whether to create ECR repository for QURL service"
  type        = bool
  default     = false
}

variable "deploy_relay_network" {
  description = "Whether this environment creates the dedicated relay DMZ network. Gates its self-apply IAM permissions so relay-dark production has no policy delta."
  type        = bool
  default     = false
}

variable "qurl_github_repo" {
  description = "GitHub repository for QURL service (for GitHub Actions trust policy)"
  type        = string
  default     = "qurl-service"

  # Bare GitHub repo name only — empty disables, otherwise letters/digits/dots/
  # underscores/dashes per GitHub's repo-name rules. Catches typos (trailing
  # spaces, accidental `org/` prefix, full URLs) at plan time rather than as a
  # confusing 401-at-assume-role post-deploy. Same shape as
  # `qurl_reverse_tunnel_server_github_repo` below.
  validation {
    condition     = var.qurl_github_repo == "" || can(regex("^[A-Za-z0-9._-]+$", var.qurl_github_repo))
    error_message = "qurl_github_repo must be empty or a bare GitHub repo name (e.g. \"qurl-service\") — no `org/` prefix, no URL, no whitespace."
  }
}

variable "qurl_reverse_tunnel_server_github_repo" {
  description = <<-EOT
    GitHub repository for the qurl-reverse-tunnel-server source. Threaded into the github_actions OIDC trust policy.

    BLAST RADIUS: trusting a repo here grants its workflows the entire `nhp-<env>-github-actions` role, NOT just `layerv/qurl-reverse-tunnel-server` ECR push. The role currently carries terraform-apply-equivalent permissions on the env: ECR push to ALL `local.ecr_repos`, full Terraform state + apply across compute/IAM/services/data, ECS / S3 deploys, and broad `ssm:PutParameter`. The publish workflow's documented use case (push `layerv/qurl-reverse-tunnel-server`, update SSM `/<env>/nhp/reverse-tunnel-server/image-tag`) is a tiny subset; a compromised trusted repo can pivot to full env control. See the SECURITY (#1121) comment block on `aws_iam_role.github_actions` for the threat model and the narrower-role refactor follow-up.

    Empty disables (useful for envs that don't yet wire the publish workflow on the source repo side). Each new entry is additive — every trusted repo MUST have branch protection on `main`, required reviews, and (for prod) a `production` GitHub Environment approval gate configured on the source repo before merging trust here.
  EOT
  type        = string
  default     = "qurl-reverse-tunnel-server"

  validation {
    condition     = var.qurl_reverse_tunnel_server_github_repo == "" || can(regex("^[A-Za-z0-9._-]+$", var.qurl_reverse_tunnel_server_github_repo))
    error_message = "qurl_reverse_tunnel_server_github_repo must be empty or a bare GitHub repo name (e.g. \"qurl-reverse-tunnel-server\") — no `org/` prefix, no URL, no whitespace."
  }
}

variable "website_api_cfn_stack_name" {
  description = "Website CDK CloudFormation stack name (e.g. LayerV-production-Api). Non-null grants the github_actions role read access on the stack so data.aws_cloudformation_stack.website_api works at plan time. Should track deploy_website_api_dns enablement. See terraform/variables.tf for the consumer-side framing of the same variable."
  type        = string
  default     = null

  validation {
    condition     = var.website_api_cfn_stack_name == null || length(var.website_api_cfn_stack_name) > 0
    error_message = "website_api_cfn_stack_name must be null or a non-empty string (an empty value would render an unscoped CFN stack ARN)."
  }
}

variable "route53_change_record_hosted_zone_ids" {
  description = <<-EOT
    Hosted zone IDs where the GitHub Actions Terraform role may call
    route53:ChangeResourceRecordSets. Keep this to the zones explicitly
    owned by the environment wiring; do not use '*' here. This is the
    guardrail for nhp#1146: a sandbox CI foothold must not be able to
    populate records in an orphan public qurl.link zone just because Route53
    has no resource-account boundary.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for zone_id in var.route53_change_record_hosted_zone_ids :
      can(regex("^Z[A-Z0-9]{8,}$", zone_id))
    ])
    error_message = "route53_change_record_hosted_zone_ids entries must be Route53 hosted zone IDs beginning with Z and at least 9 characters."
  }
}

variable "route53_change_record_name_patterns" {
  description = <<-EOT
    Normalized record-name patterns that may be changed in Terraform-created
    hosted zones whose IDs are not stable enough to pass as static inputs
    (for example the qurl-service private hosted zone). Values must be
    lowercase, trailing-dot-free exact Route53 normalized names. Because these
    patterns scope a wildcard hosted-zone ARN, keep them fully qualified to an
    environment-owned suffix; do not use broad cross-zone suffixes. Each
    pattern must be an apex-or-deeper name where the environment is the only
    authoritative zone; do not rely on suffixes also served by orphan or
    delegated hosted zones. Review any future wildcard use as a code change.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for name in var.route53_change_record_name_patterns :
      name == lower(trimsuffix(name, ".")) &&
      length(name) > 0 &&
      (
        # Static lint cannot resolve this variable's runtime values; this
        # validation is the production guard for computed-zone pattern scope.
        # Keep this exact-name-only rule aligned with the Python Route53 lint's
        # _is_narrow_route53_record_name_pattern helper.
        length(regexall("[*?]", name)) == 0
      )
    ])
    error_message = "route53_change_record_name_patterns entries must be non-empty, lowercase, trailing-dot-free exact FQDNs with no wildcards."
  }
}

# ==================== Data Sources ====================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Data source for existing OIDC provider (used when create_oidc_provider = false)
# This allows referencing an org-managed or pre-existing OIDC provider
data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

# ==================== Locals ====================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id
  partition  = split(":", data.aws_caller_identity.current.arn)[1]

  # OIDC Provider ARN - either from created resource or existing data source
  # This abstraction allows the module to work in both self-managed and org-managed scenarios
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  # ECR repository names (core repos + optional QURL)
  # NOTE: nhp-console is retained because prevent_destroy blocks removal.
  # To clean up: terraform state rm 'module.nhp.module.ecr.aws_ecr_repository.main["nhp-console"]'
  # and the corresponding lifecycle_policy and cross_account resources, then remove from this list.
  #
  # TAG-ROTATION CAVEAT: the replication-failure probe in
  # `terraform/ecr_replication_check.tf` filters `describe_images` to
  # `tagStatus == "TAGGED"`. Today every push carries an immutable
  # git-SHA tag alongside any rotating `latest` / `environment` tags,
  # so each digest stays TAGGED-visible for the lifecycle window
  # via its SHA backbone. If a future workflow ever introduces a
  # push that tags a digest ONLY with a mutable tag (no SHA backbone),
  # the probe goes blind on rotated-away digests within the look-back
  # window — see "Bonus failure mode: tag rotation" in
  # docs/runbooks/ecr-replication-failure.md. **#1489 tracks a CI lint
  # to enforce the SHA-backbone convention** so this prose guard
  # doesn't rot.
  core_ecr_repos = ["nhp-server", "nhp-ac", "nhp-console", "qurl-reverse-tunnel-server", "nhp-relay"]

  route53_change_record_hosted_zone_arns = [
    for zone_id in var.route53_change_record_hosted_zone_ids :
    "arn:aws:route53:::hostedzone/${zone_id}"
  ]
  terraform_plan_pr_s3_object_arns = distinct(compact([
    var.terraform_state_bucket != "" ? "arn:aws:s3:::${var.terraform_state_bucket}/*" : "",
    var.plugin_bucket_arn != "" ? "${var.plugin_bucket_arn}/*" : "",
    "arn:aws:s3:::${var.name_prefix}-*/*",
    "arn:aws:s3:::layerv-nhp-*/*",
    "arn:aws:s3:::bootstrap-alb-*/*",
    "arn:aws:s3:::traefik-plugins-*/*"
  ]))
  # `nhp-qurl` is the API container; `qurl-scanner-lambda` is the
  # EventBridge-driven Lambda image. Both gate on `deploy_qurl_ecr`
  # (not on the Lambda enable flag) — the repo + SSM image-tag must
  # exist before qurl-service CI can publish anything, and the Lambda
  # function itself is the only resource that gates on
  # `qurl_scanner_lambda_enabled` (see `scanner_lambda.tf` in the
  # qurl-service module). That ordering navigates the chicken-and-egg
  # between `package_type = "Image"` validating the image at Lambda
  # create time and CI being the publisher: first apply (flag OFF)
  # creates the repo + SSM param, CI publishes its first image + writes
  # the SHA to SSM, then a second apply (flag ON) creates the Lambda
  # referencing the now-existing image.
  ecr_repos = var.deploy_qurl_ecr ? concat(local.core_ecr_repos, ["nhp-qurl", "qurl-scanner-lambda"]) : local.core_ecr_repos

  # Single source of truth for "this account is the source of cross-
  # account ECR replication." Referenced by both
  # `aws_ecr_replication_configuration.cross_account.count` and the
  # `is_replication_source` output, so the two stay in mechanical
  # lockstep — a future change (e.g., adding a `var.replication_paused`
  # flag to the gate) only has to update this local. Replaces the
  # earlier output-precondition assertion approach.
  is_replication_source = var.is_primary_account && var.enable_replication && length(var.secondary_account_ids) > 0

  # PR-time Terraform plan is intentionally sandbox-only. The workflow this
  # role serves reads live sandbox state so reviewers catch API/provider
  # failures before merge, but prod remains behind the promote-to-prod approval
  # path.
  enable_terraform_plan_pr_role = var.environment == "sandbox"

  # Hoisted so consumers (the replication-check Lambda's `lifecycle.
  # precondition`) can enforce the lookback↔expiry cushion at plan
  # time instead of relying on prose. Bumping this value here AND
  # bumping `var.ecr_replication_check_lookback_hours` past it in the
  # same plan would otherwise silently re-open the silent-failure
  # window the lockstep comment fences.
  ecr_untagged_expiry_days = 7

  # ECR lifecycle policy (shared across repos)
  # Two rules: retain tagged images (git SHAs) for 90 days so prod ASGs can
  # still pull them even when sandbox has moved on, and expire untagged
  # (intermediate) images after `ecr_untagged_expiry_days` to save storage.
  #
  # DRIFT-CHECK: untagged-image expiry MUST stay larger than the ECR
  # replication-check Lambda's `LOOKBACK_HOURS` (default 25h, see
  # `terraform/variables.tf::var.ecr_replication_check_lookback_hours`).
  # If lifecycle ever runs faster than the look-back, an image could be
  # deleted before the probe inspects it — silently dropping it from the
  # failure-count metric. The Lambda's precondition (in
  # `terraform/ecr_replication_check.tf`) enforces the cushion at plan
  # time using `local.ecr_untagged_expiry_days * 24` from the output
  # below; #1476 tracks broadening this to a fleet-wide CI check.
  #
  # COST-CHECK: tagged-image expiry (90d) drives the `describe_images`
  # page-walk size on every probe tick — see the steady-state cost
  # numerics block in `terraform/lambda/ecr_replication_check.py`. The
  # docstring's "few-thousand calls/day" estimate assumes today's
  # tagged retention; bumping this to (e.g.) 180d would 2× the
  # per-tick API count even with `LOOKBACK_HOURS` unchanged, since
  # the look-back is applied client-side after pagination. Still
  # under ECR throttle today; revisit alongside #1474 if tagged
  # retention grows or `layerv/` broadens past ~10 repos.
  ecr_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after ${local.ecr_untagged_expiry_days} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = local.ecr_untagged_expiry_days
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep tagged images for 90 days (rollback window)"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "sinceImagePushed"
          countUnit      = "days"
          countNumber    = 90
        }
        action = {
          type = "expire"
        }
      }
    ]
  })

  # Cross-account ECR policy statement (shared across repos).
  # Note: secondary_account_ids should be passed from tfvars for cross-account pull.
  ecr_cross_account_policy_statements = length(var.secondary_account_ids) > 0 ? [{
    Sid    = "AllowCrossAccountPull"
    Effect = "Allow"
    Principal = {
      AWS = [for account_id in var.secondary_account_ids : "arn:aws:iam::${account_id}:root"]
    }
    Action = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImages"
    ]
  }] : []

  ecr_cross_account_policy = length(local.ecr_cross_account_policy_statements) > 0 ? jsonencode({
    Version   = "2012-10-17"
    Statement = local.ecr_cross_account_policy_statements
  }) : null

  ecr_qurl_scanner_lambda_actions = [
    "ecr:BatchGetImage",
    "ecr:GetDownloadUrlForLayer"
  ]

  # The ECR module has no cell_id input, so the wildcard after the literal
  # name_prefix separator intentionally covers every scanner cell in this
  # primary account/region, even if future function names change or drop the
  # current `cellN` segment. The trailing `*` also covers the active-recheck
  # sibling Lambda and any future scanner-prefixed sibling in the same
  # account/region. Issue #2705 tracks narrowing this once exact scanner
  # function identity is available here without introducing a module cycle.
  # Keep this pattern in lockstep with `scanner_lambda_function_name` and
  # `scanner_active_recheck_function_name` in modules/qurl-service/scanner_lambda.tf.
  # Both modules are wired from terraform/main.tf with the same
  # `local.name_prefix`; do not split those root inputs without also narrowing
  # or reworking this SourceArn.
  ecr_qurl_scanner_lambda_source_arn = "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-*qurl-scanner*"

  # Lambda functions need the ECR service principal to retrieve images for
  # inactive image-backed functions. Without this, the qurl-scanner Lambda can
  # enter ImageAccessDenied after the first idle cycle even though EventBridge
  # keeps firing the schedule.
  ecr_qurl_scanner_lambda_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.ecr_cross_account_policy_statements, [{
      Sid    = "LambdaECRImageRetrievalPolicy"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = local.ecr_qurl_scanner_lambda_actions
      Condition = {
        StringLike = {
          # SourceArn already pins account and region. aws:SourceAccount would
          # be defense-in-depth here, but it does not change confinement and
          # would make Terraform own a broader condition shape than needed.
          "aws:SourceArn" = local.ecr_qurl_scanner_lambda_source_arn
        }
      }
    }])
  })

  # Repository policies are Terraform-owned only in the primary account because
  # prod repositories are replication-created in the secondary account. Issue
  # #2699 tracks Terraform ownership for the replicated qurl-scanner Lambda policy.
  # Keep non-scanner repos behind the `secondary_account_ids` branch: their
  # policy is `local.ecr_cross_account_policy`, which is null without
  # secondary pull accounts. The scanner repo is the only entry unconditional
  # with respect to secondary pull accounts because it uses the always-non-null
  # Lambda retrieval policy.
  ecr_repository_policy_repos = var.is_primary_account ? distinct(concat(
    length(var.secondary_account_ids) > 0 ? local.ecr_repos : [],
    var.deploy_qurl_ecr ? ["qurl-scanner-lambda"] : []
  )) : []

  # Shared matcher for the scanner policy fences below. `generated` guards the
  # rendered local policy against future structural drift; `wired` is the
  # load-bearing primary-account check that the scanner repo uses that policy.
  ecr_qurl_scanner_lambda_policy_match_sources = {
    generated = jsondecode(local.ecr_qurl_scanner_lambda_policy).Statement
    wired     = try(jsondecode(aws_ecr_repository_policy.cross_account["qurl-scanner-lambda"].policy).Statement, [])
  }

  ecr_qurl_scanner_lambda_policy_has_expected_retrieval_grant = {
    for source, statements in local.ecr_qurl_scanner_lambda_policy_match_sources : source => anytrue([
      for statement in statements :
      try(statement.Sid, "") == "LambdaECRImageRetrievalPolicy" &&
      contains(flatten([try(statement.Principal.Service, [])]), "lambda.amazonaws.com") &&
      toset(flatten([try(statement.Action, [])])) == toset(local.ecr_qurl_scanner_lambda_actions) &&
      try(statement.Condition.StringLike["aws:SourceArn"], "") == local.ecr_qurl_scanner_lambda_source_arn
    ])
  }

  # Account ID to use in ECR URLs and IAM resource ARNs for SECONDARY accounts:
  # - With replication enabled: use the local account (images live here, replicated
  #   from the primary account by aws_ecr_replication_configuration).
  # - Without replication: fall back to the primary account (cross-account pull).
  # Defined here (rather than in a second locals block) so all account/region
  # derived values stay in one place.
  secondary_ecr_account_id = var.enable_replication ? local.account_id : var.primary_account_id
}

# ============================================================================
# PRIMARY ACCOUNT RESOURCES (sandbox - owns ECR)
# ============================================================================

# ECR Repositories - consolidated with for_each
#
# `depends_on` forces the IAM perms granted in
# `aws_iam_policy.terraform_apply_services` (notably `ecr:CreateRepository`)
# to land before any first-time repo create on this for_each. Without it,
# Terraform schedules the policy update and the new repo create in parallel
# and the create races against IAM propagation. Existing repos see no churn
# from the dependency — `depends_on` doesn't trigger replacement.
resource "aws_ecr_repository" "main" {
  for_each = var.is_primary_account ? toset(local.ecr_repos) : []

  name                 = "layerv/${each.key}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ecr-${each.key}"
    Component = "ecr"
  })

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [aws_iam_role_policy_attachment.terraform_apply_services]
}

resource "aws_ecr_lifecycle_policy" "main" {
  for_each = var.is_primary_account ? toset(local.ecr_repos) : []

  repository = aws_ecr_repository.main[each.key].name
  policy     = local.ecr_lifecycle_policy
}

# Repository policy. Non-scanner repos use the cross-account pull policy; the
# qurl-scanner Lambda repo also gets the Lambda service-principal image
# retrieval grant that prevents ImageAccessDenied after idle/reactivation.
#
# Kept active even when var.enable_replication is true so that:
#   - secondary accounts can still pull from the primary registry as a
#     fall-back during the rollout window before replication has copied
#     every image they need;
#   - operators can manually pull a specific image from the source registry
#     for diagnostics without needing to wait for replication.
# Once every secondary account has been on its local replicated registry
# for at least one full rollback window (90 days, see local.ecr_lifecycle_policy)
# this resource can be removed in a follow-up PR -- track in the same
# follow-up that adds destination-side lifecycle policies (issue #901).
resource "aws_ecr_repository_policy" "cross_account" {
  for_each = toset(local.ecr_repository_policy_repos)

  repository = aws_ecr_repository.main[each.key].name
  policy     = each.key == "qurl-scanner-lambda" ? local.ecr_qurl_scanner_lambda_policy : local.ecr_cross_account_policy
}

# Regression fences for the sandbox incident fixed by PR #2698: the generated
# scanner repository policy must keep the Lambda service-principal image
# retrieval grant, and the scanner repo resource must actually use that policy.
# Runtime policy drift is still covered by the rollout ledger's
# idle/reactivation check.
resource "terraform_data" "qurl_scanner_lambda_policy_fence" {
  # Deliberately keep one stable, guarded fence resource instead of switching
  # addresses with count/for_each. Secondary/prod remains inert for repo wiring
  # until issue #2699 brings replicated scanner policy ownership into Terraform.
  #
  # `input` surfaces the watched value in the plan and re-runs the fence
  # whenever it changes. The rendered policy already embeds the actions and
  # source ARN, so it alone subsumes every input the preconditions check.
  input = local.ecr_qurl_scanner_lambda_policy

  lifecycle {
    precondition {
      condition     = !var.deploy_qurl_ecr || local.ecr_qurl_scanner_lambda_policy_has_expected_retrieval_grant.generated
      error_message = "qurl-scanner Lambda ECR policy must include LambdaECRImageRetrievalPolicy for lambda.amazonaws.com with only the expected scanner Lambda ECR actions scoped by aws:SourceArn."
    }

    precondition {
      condition     = !var.deploy_qurl_ecr || !var.is_primary_account || local.ecr_qurl_scanner_lambda_policy_has_expected_retrieval_grant.wired
      error_message = "qurl-scanner-lambda must be wired to local.ecr_qurl_scanner_lambda_policy so Terraform applies the Lambda retrieval grant to the scanner repository."
    }
  }
}

# ============================================================================
# ECR CROSS-ACCOUNT REPLICATION
# ============================================================================
#
# Replicates images from the primary account (sandbox) to secondary accounts
# (prod) so each account has its own copy. This eliminates sandbox as a
# production runtime dependency.
#
# Two resources work together:
#
# 1. Replication Configuration (PRIMARY account):
#    - aws_ecr_replication_configuration pushes images to secondary registries
#    - Uses a repository_filter to scope replication to "layerv/" prefix
#    - One rule per secondary account (same region)
#
# 2. Registry Policy (SECONDARY account):
#    - aws_ecr_registry_policy grants the primary account's ECR replication
#      service permission to create repositories and push images
#    - Without this, replication attempts from the primary account are denied
#
# Singleton resources -- IMPORTANT
# --------------------------------
# Both aws_ecr_replication_configuration and aws_ecr_registry_policy are
# *registry-wide singletons* per (account, region). Terraform will overwrite
# any existing replication configuration or registry policy in the target
# account/region. Before enabling this in a new account, run
# `aws ecr describe-registry` and `aws ecr get-registry-policy` to confirm
# nothing else owns these resources, otherwise you will silently clobber
# unrelated rules.
#
# Lifecycle policies are NOT replicated -- IMPORTANT
# --------------------------------------------------
# Replicated repositories are created automatically in the destination account
# but DO NOT inherit any lifecycle policies from the source. Without an
# explicit destination-side lifecycle policy, replicated images will accumulate
# indefinitely. Tracked as follow-up in issue #901; that PR will add a
# destination-side lifecycle policy resource so secondary accounts retain only
# the same 90-day rollback window the source uses.
#
# Rollout order
# -------------
# Because replication writes from PRIMARY -> SECONDARY, the destination must
# trust the source BEFORE the source starts pushing. Apply in this order:
#
#   1. terraform apply on the SECONDARY account with `enable_replication=true`
#      (creates the registry policy that allows the primary account in).
#   2. terraform apply on the PRIMARY account with `enable_replication=true`
#      (creates the replication configuration that starts copying images).
#   3. Push or re-tag a known image in the primary account and confirm it
#      shows up in the secondary account's ECR within ~5 minutes.
#   4. Only then is it safe to flip secondary-account services to pull from
#      the local registry (via `enable_replication=true` propagating into the
#      IAM role policy resource ARNs below).
#
# Reverting is the inverse: turn off replication on the primary first so
# nothing is in flight, then on the secondary.
# ============================================================================

# Primary account: replicate images to each secondary account.
# Gate is in `local.is_replication_source` so the `is_replication_source`
# output stays mechanically aligned with whether this resource fires.
resource "aws_ecr_replication_configuration" "cross_account" {
  count = local.is_replication_source ? 1 : 0

  replication_configuration {
    rule {
      dynamic "destination" {
        for_each = var.secondary_account_ids
        content {
          region      = local.region
          registry_id = destination.value
        }
      }

      repository_filter {
        filter      = "layerv/"
        filter_type = "PREFIX_MATCH"
      }
    }
  }
}

# Secondary account: allow primary account's ECR replication service to push images.
#
# NOTE: previous revisions of this policy included a defense-in-depth
#   Condition.StringEquals: { "aws:SourceAccount": var.primary_account_id }
# ECR's cross-account replication does not populate aws:SourceAccount in the
# authorization context, so that Condition always evaluated to the implicit
# deny and all replication attempts failed with DESTINATION_REGISTRY_ACCESS_DENIED
# (observed empirically during the 2026-04-24 prod release incident; registry
# was manually corrected and this change brings terraform back in sync).
#
# The Principal scoping alone is load-bearing: only identities in the
# primary account can match, and AWS's own reference policy examples for
# cross-account ECR replication omit any aws:SourceAccount / aws:SourceArn
# condition for the same reason (ECR replication doesn't populate either
# key). See docs/runbooks/ecr-replication-failure.md "Known gotcha"
# and docs/incidents/2026-04-24-ecr-source-account-trap.md for the
# reviewer-facing rule + audit of the same pattern across modules.
resource "aws_ecr_registry_policy" "replication" {
  count = !var.is_primary_account && var.enable_replication && var.primary_account_id != "" ? 1 : 0

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowReplicationFromPrimary"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.primary_account_id}:root"
        }
        Action = [
          "ecr:CreateRepository",
          "ecr:ReplicateImage"
        ]
        Resource = "arn:aws:ecr:${local.region}:${local.account_id}:repository/layerv/*"
      }
    ]
  })
}

# ============================================================================
# GITHUB OIDC PROVIDER
# ============================================================================
#
# The OIDC provider enables GitHub Actions to authenticate with AWS using
# OpenID Connect, eliminating the need for long-lived credentials.
#
# This resource is CONDITIONAL based on `create_oidc_provider`:
# - true (default): Creates the OIDC provider in this account
# - false: Uses data source to reference existing provider (org-managed or pre-existing)
#
# Set create_oidc_provider = false when:
# - Organization SCP blocks iam:CreateOpenIDConnectProvider
# - OIDC provider is managed centrally by platform team
# - Provider already exists from another terraform workspace
# ============================================================================

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-oidc-github"
    Component = "ecr"
  })

  lifecycle {
    ignore_changes  = [thumbprint_list]
    prevent_destroy = true
  }
}

# ============================================================================
# GITHUB ACTIONS IAM ROLE
# ============================================================================
#
# Per-environment IAM role for GitHub Actions CI/CD.
# Named `nhp-${environment}-github-actions` to support parallel environments.
#
# Trust Policy:
# - Allows GitHub Actions from specified org/repo to assume this role
# - Restricts to main branch and named environments (sandbox, production)
# - Supports both nhp and traefik-plugins repositories
#
# Permissions are split across multiple inline policies due to IAM size limits.
# ============================================================================

resource "aws_iam_role" "github_actions" {
  name        = "nhp-${var.environment}-github-actions"
  description = "GitHub Actions role for ${var.github_org}/${var.github_repo} (${var.environment})"

  # The sandbox qURL live-environment mutex permits a two-hour queue wait
  # inside a three-hour job. Callers still have to request this duration; this
  # only raises the role ceiling so lock-bearing sandbox jobs do not lose their
  # credentials mid-wait or before exact-owner release. Keep prod at AWS's
  # one-hour default because no prod workflow needs the wider session.
  max_session_duration = var.environment == "sandbox" ? 10800 : 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        # Allow main branch and environment-based deployments for:
        # - Main NHP repo
        # - Traefik plugins repo
        # - NHP server plugin repos (nhp-plugins-passcode, nhp-plugins-oidc, etc.)
        # Environment-based: used by deploy jobs with `environment: sandbox/production`
        #
        # SECURITY (#1121): the `pull_request` sub claim was removed
        # from the main NHP repo entry (below) — PR-time workflows
        # must NOT be able to assume this role. Any PR can run
        # arbitrary code during `terraform plan` (provider hooks,
        # external data sources) which could exfil short-lived STS
        # creds and pivot to full IAM admin via
        # iam:UpdateAssumeRolePolicy on this very role. The
        # terraform-validate PR job has been moved to a lint-only
        # shape that needs no AWS at all. Note: the traefik-plugins,
        # plugin-repos, and qurl-service entries never listed
        # `pull_request` and are unchanged; do not add it to any of
        # them without revisiting this threat model.
        StringLike = {
          "token.actions.githubusercontent.com:sub" = concat(
            # Main NHP repo
            [
              "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
              "repo:${var.github_org}/${var.github_repo}:environment:sandbox",
              "repo:${var.github_org}/${var.github_repo}:environment:production"
            ],
            # Traefik plugins repo
            var.traefik_plugins_github_repo != "" ? [
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:ref:refs/heads/main",
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:environment:sandbox",
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:environment:staging",
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:environment:production"
            ] : [],
            # NHP Server plugin repos (passcode, oidc, etc.)
            flatten([
              for repo in var.plugin_repos : [
                "repo:${var.github_org}/${repo}:ref:refs/heads/main",
                "repo:${var.github_org}/${repo}:environment:sandbox",
                "repo:${var.github_org}/${repo}:environment:production"
              ]
            ]),
            # QURL Service repo
            var.deploy_qurl_ecr && var.qurl_github_repo != "" ? [
              "repo:${var.github_org}/${var.qurl_github_repo}:ref:refs/heads/main",
              "repo:${var.github_org}/${var.qurl_github_repo}:environment:sandbox",
              "repo:${var.github_org}/${var.qurl_github_repo}:environment:production"
            ] : [],
            # QURL Service gated pre-merge Environment — SANDBOX-ONLY.
            #
            # qurl-service split its shared `sandbox` Environment so main-branch
            # deploys run ungated (continuous deployment) while same-repo PR code
            # (the qv2 pre-merge smoke and its docker-build image push) stays
            # behind a required-reviewers approval on the `sandbox-premerge`
            # Environment before it can assume this role. Like every entry here it
            # is an `:environment:` claim (no bare `:ref:refs/heads/main`), so the
            # GH Environment approval gate is the security boundary — see the
            # qurl-reverse-tunnel-server threat-model note below.
            #
            # Gated on `var.environment == "sandbox"` (mirrors
            # `enable_terraform_plan_pr_role` above) so this claim never lands on
            # the `nhp-prod-github-actions` role. `sandbox-premerge` exists only
            # for qurl-service's sandbox PR smoke, which assumes the sandbox-
            # account role; because it carries UNTRUSTED PR code, least-privilege
            # matters more than for the trusted merged-code `:environment:sandbox`
            # / `:production` claims — the prod role must not trust it.
            #
            # NOTE for reviewers of the `sandbox-premerge` GH Environment: this
            # role is terraform-apply-equivalent on sandbox (EC2/networking, IAM,
            # ECS, SES, data, qurl-link CloudFront/S3 — not just ECR push), and a
            # PR runs arbitrary PR-head code in its steps. So approving a
            # `sandbox-premerge` deployment hands that PR code the full sandbox
            # apply-equivalent STS creds — the approval is a CODE-TRUST gate, not
            # a deploy-confirmation click. Vet the PR's workflow/Dockerfile/test
            # changes before approving. Narrowing this to an ECR/ECS-scoped role
            # is tracked as a follow-up (nhp#3182).
            var.deploy_qurl_ecr && var.qurl_github_repo != "" && var.environment == "sandbox" ? [
              "repo:${var.github_org}/${var.qurl_github_repo}:environment:sandbox-premerge"
            ] : [],
            # qurl-reverse-tunnel-server repo (publishes its image to ECR).
            #
            # Intentionally NOT gated on a `deploy_frps`-style flag (asymmetric
            # vs. the `qurl_github_repo` entry above, which is gated on
            # `deploy_qurl_ecr`). The trust grant must precede `deploy_frps =
            # true` in any env: the publish workflow has to push at least one
            # `layerv/qurl-reverse-tunnel-server` image into ECR before the
            # ASG can boot (otherwise instances crash-loop on `docker pull` of
            # the `v0.0.0-bootstrap` placeholder — see `frps_image_tag` in
            # `terraform/variables.tf`). The companion ECR repo creation in
            # nhp #1555 lands `qurl-reverse-tunnel-server` in
            # `local.core_ecr_repos` for the same reason — present in every
            # primary account regardless of whether `deploy_frps` is on yet.
            #
            # Sub-claim shape is intentionally narrower than the four legacy
            # entries above: only `:environment:` claims, no bare
            # `:ref:refs/heads/main`. A bare main-branch claim would defeat
            # the GH Environment approval gates — any workflow run on the
            # trusted repo's main that omits `environment:` would still
            # satisfy that sub claim and get the full
            # `nhp-<env>-github-actions` role (terraform-apply-equivalent on
            # the env). With upstream qurl-reverse-tunnel-server #82
            # declaring `environment: ${{ github.event_name != 'pull_request'
            # && 'sandbox' || null }}`, the bare-main entry would cover zero
            # real workflow runs that `:environment:sandbox` doesn't already
            # cover. This is the shape #1574 is converging the legacy
            # entries to.
            #
            # The `:environment:production` arm is forward-looking — upstream
            # #82's publish job currently only emits `environment: sandbox`,
            # so nothing in qurl-reverse-tunnel-server matches the production
            # claim today. Kept here so a future prod publish job lands
            # without a Terraform round-trip; don't grep for a workflow that
            # doesn't exist yet.
            var.qurl_reverse_tunnel_server_github_repo != "" ? [
              "repo:${var.github_org}/${var.qurl_reverse_tunnel_server_github_repo}:environment:sandbox",
              "repo:${var.github_org}/${var.qurl_reverse_tunnel_server_github_repo}:environment:production"
            ] : []
          )
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-github-actions"
    Component = "ecr"
  })
}

# ECR permissions - different for primary vs secondary account
resource "aws_iam_role_policy" "ecr_push" {
  name = "ecr-push"
  role = aws_iam_role.github_actions.id

  policy = var.is_primary_account ? jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid      = "ECRAuth"
          Effect   = "Allow"
          Action   = ["ecr:GetAuthorizationToken"]
          Resource = "*"
        },
        {
          Sid    = "ECRPush"
          Effect = "Allow"
          Action = [
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "ecr:PutImage",
            "ecr:InitiateLayerUpload",
            "ecr:UploadLayerPart",
            "ecr:CompleteLayerUpload",
            "ecr:DescribeRepositories",
            "ecr:DescribeImages"
          ]
          Resource = [for repo in local.ecr_repos : aws_ecr_repository.main[repo].arn]
        },
      ],
      var.deploy_qurl_ecr ? [
        {
          Sid      = "QURLPrImageCleanup"
          Effect   = "Allow"
          Action   = ["ecr:BatchDeleteImage"]
          Resource = [aws_ecr_repository.main["nhp-qurl"].arn]
        }
      ] : [],
      [
        {
          Sid    = "ECRReplication"
          Effect = "Allow"
          Action = [
            "ecr:PutReplicationConfiguration",
            "ecr:DescribeRegistry"
          ]
          Resource = "*"
        },
        {
          Sid      = "ECRReplicationSLR"
          Effect   = "Allow"
          Action   = ["iam:CreateServiceLinkedRole"]
          Resource = "arn:aws:iam::*:role/aws-service-role/replication.ecr.amazonaws.com/*"
          Condition = {
            StringEquals = {
              "iam:AWSServiceName" = "replication.ecr.amazonaws.com"
            }
          }
        }
      ]
    )
    }) : jsonencode({
    # Secondary account - ECR pull (local registry when replicated, cross-account otherwise)
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPull"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages"
        ]
        Resource = [for repo in local.ecr_repos : "arn:aws:ecr:${local.region}:${local.secondary_ecr_account_id}:repository/layerv/${repo}"]
      },
      {
        Sid    = "ECRRegistryPolicy"
        Effect = "Allow"
        Action = [
          "ecr:PutRegistryPolicy",
          "ecr:GetRegistryPolicy",
          "ecr:DeleteRegistryPolicy",
          "ecr:DescribeRegistry"
        ]
        Resource = "*"
      }
    ]
  })
}

# Terraform state permissions for GitHub Actions
resource "aws_iam_role_policy" "terraform_state" {
  count = var.terraform_state_bucket != "" ? 1 : 0

  name = "terraform-state"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3StateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.terraform_state_bucket}",
          "arn:aws:s3:::${var.terraform_state_bucket}/*"
        ]
      },
      {
        Sid    = "DynamoDBLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.terraform_lock_table}"
      }
    ]
  })
}

# Context Lookups and Terraform Apply Policy
resource "aws_iam_role_policy" "context_lookups" {
  name = "context-lookups"
  role = aws_iam_role.github_actions.id

  # Keep the disabled/prod JSON document byte-for-byte compatible with the
  # existing policy. The explicit jsonencode branches are intentional: the
  # static IAM coverage lint walks both branches, whereas it cannot evaluate a
  # computed Statement = concat(...) expression.
  policy = var.deploy_relay_network ? jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ContextLookups"
        Effect = "Allow"
        Action = [
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways",
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ssm:GetParameter",
          "route53:ListHostedZones",
          "route53:ListHostedZonesByName"
        ]
        Resource = "*"
      },
      {
        Sid    = "ASGRefreshDescribe"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeInstanceRefreshes",
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "ASGRefreshManage"
        Effect = "Allow"
        Action = [
          "autoscaling:StartInstanceRefresh",
          "autoscaling:CancelInstanceRefresh",
          "autoscaling:SuspendProcesses",
          "autoscaling:ResumeProcesses"
        ]
        Resource = "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/layerv-nhp-*"
      },
      {
        # Blue/green Switch Traffic clears stale AC-to-server assignments so the
        # next AC registration builds fresh assignments pointing at the new active
        # servers. See .github/scripts/clear-ac-assignments.sh.
        Sid    = "DynamoDBClearACAssignments"
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-${var.environment}-*-ac-assignments"
      }
    ]
    }) : jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ContextLookups"
        Effect = "Allow"
        Action = [
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways",
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ssm:GetParameter",
          "route53:ListHostedZones",
          "route53:ListHostedZonesByName"
        ]
        Resource = "*"
      },
      {
        Sid    = "ASGRefreshDescribe"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeInstanceRefreshes",
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "ASGRefreshManage"
        Effect = "Allow"
        Action = [
          "autoscaling:StartInstanceRefresh",
          "autoscaling:CancelInstanceRefresh",
          "autoscaling:SuspendProcesses",
          "autoscaling:ResumeProcesses"
        ]
        Resource = "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/layerv-nhp-*"
      },
      {
        Sid    = "SSMHealthCheck"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation"
        ]
        Resource = [
          "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
          "arn:aws:ssm:${local.region}::document/AWS-RunShellScript",
          "arn:aws:ssm:${local.region}:${local.account_id}:document/AWS-RunShellScript"
        ]
      },
      {
        # Blue/green Switch Traffic clears stale AC-to-server assignments so the
        # next AC registration builds fresh assignments pointing at the new active
        # servers. See .github/scripts/clear-ac-assignments.sh.
        Sid    = "DynamoDBClearACAssignments"
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-${var.environment}-*-ac-assignments"
      }
    ]
  })
}

# qurl-service#1237: the pre-deploy agent-key inventory gate. The promotion
# workflow runs the gate binary out of the qurl image immediately before
# deploy-qurl; it needs a complete strongly consistent Scan of exactly the two
# qurl agent-identity tables. The sandbox-only second statement supports the
# governed schema-v2 canary binding verifier from qurl-service#1418; it reads
# only the Control connector-authority table and never ships to production.
#
# Deliberately its OWN inline policy rather than another statement inside
# `context_lookups`: that policy is a reviewed relay-DMZ boundary resource
# (DMZ_BOUNDARY_ADDRESS_PATTERNS in .github/scripts/check-relay-dmz-plan.py),
# and ordinary deploys must leave it a no-op. Folding an unrelated CI read into
# it fails the DMZ plan contract and drags this grant into a security-boundary
# review it has nothing to do with.
#
# Inline rather than a managed policy because the github_actions role already
# carries the AWS default maximum of 10 attached managed policies
# (GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT in
# .github/scripts/check-terraform-iam-coverage.py); an 11th attachment would
# fail at apply. The role's inline aggregate has room for a document this small.
#
# Scope note: this is the CI/promotion principal and is NOT nhp-server's task
# role. docs/design/QURL_AGENT_KEYS_SCHEMA.md keeps that reader Scan-free, and
# tests/scripts/test_check_terraform_plan_pr_policy_readonly.py fences it
# against the `dynamodb_read` policy. That fence covers a different document
# and is unaffected here — do not consolidate this statement into it.
resource "aws_iam_role_policy" "qurl_agent_key_inventory" {
  name = "qurl-agent-key-inventory"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid    = "DynamoDBQurlAgentKeyInventoryGate"
        Effect = "Allow"
        Action = ["dynamodb:Scan"]
        Resource = [
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-${var.environment}-*-qurl-api-keys",
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-${var.environment}-*-qurl-agent-keys"
        ]
      }],
      var.environment == "sandbox" ? [{
        Sid      = "DynamoDBQurlCanaryBindingVerifier"
        Effect   = "Allow"
        Action   = ["dynamodb:Scan"]
        Resource = ["arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-sandbox-control-connector-authority"]
      }] : []
    )
  })
}

# Cloud Map instance registration for the cell-local qurl-api name.
#
# A private cell exposes its internal qurl ALB as qurl-api.<namespace>, and that
# name CANNOT be a Route53 record: the namespace's hosted zone is Cloud Map
# owned and Route53 refuses direct writes to it ("can only be managed through
# AWS Cloud Map"). The only way to publish the name is an
# aws_service_discovery_instance carrying AWS_INSTANCE_CNAME, whose CRUD is
# Register/DeregisterInstance -- neither of which the role's existing
# servicediscovery grants cover (they are Get*/List* plus namespace and service
# creation).
#
# This is a SEPARATE inline policy on purpose, for two reasons documented in
# terraform/CLAUDE.md and enforced by CI:
#   * the relay-DMZ boundary resources (context_lookups, context_lookups_relay_ssm,
#     terraform_apply_relay_dmz) must stay no-op in ordinary deploys, so an
#     unrelated statement added to one of them breaks check-relay-dmz-plan.py;
#   * the nhp-<env>-github-actions role sits at the AWS default 10/10 attached
#     managed policies, so this cannot be an 11th managed attachment.
#
# Scoped to instances under this environment's own services rather than "*".
# The deploy role could not modify network ACL entries at all -- no attached
# policy granted a single NetworkAcl action -- so moving the public UDP client
# edge from 62206 to 443 failed mid-apply:
#
#   Error: updating EC2 Network ACL (acl-0b57c270c6ec7a018): deleting Entry:
#   UnauthorizedOperation ... not authorized to perform: ec2:DeleteNetworkAclEntry
#
# A NACL entry is keyed by rule number, so terraform changes a port by deleting
# and recreating the entry; without the delete verb the apply gets half way and
# leaves the fleet on mixed ports.
#
# A NEW INLINE policy rather than an addition to an existing one: the role is at
# the 10 attached-managed-policy limit, and the existing context-lookups policy
# is a read-only lookup surface that must not grow write verbs.
#
# Scoped to network ACLs in this account and region. ReplaceNetworkAclEntry is
# included because terraform uses it for an in-place rule-number-stable change;
# CreateNetworkAcl/DeleteNetworkAcl are deliberately NOT granted -- this permits
# editing the reviewed ACLs' rules, not creating or destroying the ACLs.
resource "aws_iam_role_policy" "network_acl_entries" {
  name = "network-acl-entries"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "NetworkAclEntryWrite"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:ReplaceNetworkAclEntry",
        ]
        Resource = [
          "arn:aws:ec2:${local.region}:${local.account_id}:network-acl/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy" "servicediscovery_instance_registration" {
  name = "servicediscovery-instance-registration"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudMapCellInstanceRegistration"
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance",
        ]
        Resource = [
          "arn:aws:servicediscovery:${local.region}:${local.account_id}:service/*",
        ]
      },
    ]
  })
}

# Run Command is needed only by the relay-enabled sandbox integration and is
# isolated from the context-lookups policy so production retains its existing
# document unchanged. SendCommand authorization evaluates both the document
# and target node resources; GetCommandInvocation exposes no resource type.
resource "aws_iam_role_policy" "context_lookups_relay_ssm" {
  count = var.deploy_relay_network ? 1 : 0

  name = "context-lookups-relay-ssm"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SSMHealthCheckDocument"
        Effect   = "Allow"
        Action   = "ssm:SendCommand"
        Resource = "arn:aws:ssm:${local.region}::document/AWS-RunShellScript"
      },
      {
        # Environment is the strongest tag shared by every existing sandbox
        # Run Command target (server, AC, relay, and smoke-test hosts). The
        # shared deploy role also drives the provisioned cell1 server fleet,
        # whose environment tag is "sandbox-cell1". A relay-only
        # Component/Service condition would break those probes.
        Sid      = "SSMHealthCheckSandboxInstances"
        Effect   = "Allow"
        Action   = "ssm:SendCommand"
        Resource = "arn:aws:ec2:${local.region}:${local.account_id}:instance/*"
        Condition = {
          StringEquals = {
            "ssm:resourceTag/Environment" = [
              "sandbox",
              "sandbox-cell1",
            ]
          }
        }
      },
      {
        Sid      = "SSMHealthCheckInvocation"
        Effect   = "Allow"
        Action   = "ssm:GetCommandInvocation"
        Resource = "*"
      }
    ]
  })
}

# Custom managed policy for Terraform read permissions
# This avoids the chicken-and-egg problem (CI can't add permissions it doesn't have)
# while following least privilege (only read access to services we use)
resource "aws_iam_policy" "terraform_read" {
  name        = "nhp-${var.environment}-github-actions-terraform-read"
  description = "Read-only permissions for Terraform to read resource state (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Read"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:Get*"
        ]
        Resource = "*"
      },
      {
        # The attended Control first-apply routing audit enumerates these
        # regional and global Direct Connect surfaces before it accepts a VPC
        # CIDR. Keep this list exact and in lockstep with both audit scripts;
        # broad Direct Connect wildcards are unnecessary for read-only proof.
        Sid    = "DirectConnectRead"
        Effect = "Allow"
        Action = [
          "directconnect:DescribeConnections",
          "directconnect:DescribeVirtualInterfaces",
          "directconnect:DescribeDirectConnectGateways",
          "directconnect:DescribeDirectConnectGatewayAssociations",
          "directconnect:DescribeDirectConnectGatewayAssociationProposals"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Read"
        Effect = "Allow"
        Action = [
          "s3:Get*",
          "s3:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRead"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Route53Read"
        Effect = "Allow"
        Action = concat(
          [
            "route53:Get*",
            "route53:List*",
          ],
          var.deploy_relay_network ? [
            "route53resolver:Get*",
            "route53resolver:List*",
          ] : [],
        )
        Resource = "*"
      },
      {
        Sid    = "CloudWatchRead"
        Effect = "Allow"
        Action = [
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:List*",
          "logs:FilterLogEvents",
          "logs:StartLiveTail"
        ]
        Resource = "*"
      },
      {
        Sid    = "EFSRead"
        Effect = "Allow"
        Action = [
          "elasticfilesystem:Describe*",
          "elasticfilesystem:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "LambdaRead"
        Effect = "Allow"
        Action = [
          "lambda:Get*",
          "lambda:List*"
        ]
        Resource = "*"
      },
      {
        # This Lambda exposes read-only semantic validation that cannot be
        # expressed with Lambda Get/List APIs. Keep the shared deploy role on
        # the same exact qualified target as the isolated PR-plan role below.
        # Terraform invokes this data source during refresh, before it can apply
        # any pending IAM-policy change.
        Sid      = "RelayIdentityStatusInvoke"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:$LATEST"]
      },
      {
        Sid    = "AutoScalingRead"
        Effect = "Allow"
        Action = [
          "autoscaling:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ELBRead"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMRead"
        Effect = "Allow"
        Action = [
          "ssm:Describe*",
          "ssm:Get*",
          "ssm:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityServicesRead"
        Effect = "Allow"
        Action = [
          "guardduty:Get*",
          "guardduty:List*",
          "securityhub:Describe*",
          "securityhub:Get*",
          "securityhub:List*",
          "config:Describe*",
          "config:Get*",
          "config:List*"
        ]
        Resource = "*"
      },
      {
        # SECURITY (#1125): scope resource-scoped metadata actions
        # (kms:DescribeKey, kms:GetKeyPolicy, kms:ListGrants, etc.) to keys
        # owned by this account. Uses StringEqualsIfExists because some
        # actions in this block (kms:ListKeys, kms:ListAliases) are
        # non-resource-scoped — aws:ResourceAccount resolves absent for
        # those, and IfExists permits them; a plain StringEquals would
        # deny them. A proper key-ARN allowlist that retires this whole
        # IfExists shape is tracked in #1521.
        Sid    = "KMSMetadataRead"
        Effect = "Allow"
        Action = [
          "kms:Describe*",
          "kms:Get*",
          "kms:List*"
        ]
        Resource = "*"
        Condition = {
          StringEqualsIfExists = {
            "aws:ResourceAccount" = local.account_id
          }
        }
      },
      {
        # SECURITY (#1125): block kms:Decrypt against keys owned by other
        # accounts via aws:ResourceAccount (resolves to the account of the
        # *resource*; kms:CallerAccount would resolve to the role's own
        # account and be a tautology in an identity-based policy).
        # Tightened further by #1521, which replaces Resource = "*" with
        # an explicit ARN allowlist after a CloudTrail audit.
        Sid    = "KMSDecryptInAccount"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "EventBridgeRead"
        Effect = "Allow"
        Action = [
          "events:Describe*",
          "events:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSRead"
        Effect = "Allow"
        Action = [
          "sns:Get*",
          "sns:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ACMRead"
        Effect = "Allow"
        Action = [
          "acm:Describe*",
          "acm:Get*",
          "acm:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ServiceDiscoveryRead"
        Effect = "Allow"
        Action = [
          "servicediscovery:Get*",
          "servicediscovery:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:Describe*",
          "secretsmanager:Get*",
          "secretsmanager:List*"
        ]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"
      },
      {
        Sid    = "WAFRead"
        Effect = "Allow"
        Action = [
          "wafv2:Get*",
          "wafv2:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontRead"
        Effect = "Allow"
        Action = [
          "cloudfront:Get*",
          "cloudfront:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRRead"
        Effect = "Allow"
        Action = [
          "ecr:Describe*",
          "ecr:Get*",
          "ecr:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSRead"
        Effect = "Allow"
        Action = [
          "ecs:Describe*",
          "ecs:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBRead"
        Effect = "Allow"
        Action = [
          "dynamodb:Describe*",
          "dynamodb:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ElastiCacheRead"
        Effect = "Allow"
        Action = [
          "elasticache:Describe*",
          "elasticache:List*"
        ]
        Resource = "*"
      },
      {
        # GetItem needed for terraform plan to refresh aws_dynamodb_table_item state
        Sid    = "DynamoDBGetItem"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-*"
      },
      {
        Sid    = "ChatbotRead"
        Effect = "Allow"
        Action = [
          "chatbot:Describe*",
          "chatbot:Get*",
          "chatbot:List*"
        ]
        Resource = "*"
      }
    ]
  })

  lifecycle {
    postcondition {
      # IAM rejects customer-managed policy documents above 6,144
      # non-whitespace characters. jsonencode emits no insignificant
      # whitespace, so this checks the exact provider payload before apply.
      condition     = length(self.policy) <= 6144
      error_message = "terraform_read exceeds IAM's 6,144-character customer-managed policy quota; consolidate statements within the existing attachment budget before applying."
    }
  }
}

resource "aws_iam_role_policy_attachment" "terraform_read" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_read.arn
}

resource "aws_iam_role" "github_actions_terraform_plan_pr" {
  count = local.enable_terraform_plan_pr_role ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-terraform-plan-pr"
  description = "Read-only GitHub Actions role for PR Terraform plans (${var.environment})"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        # AWS IAM can evaluate the GitHub OIDC audience and subject here, but
        # GitHub custom claims such as `workflow_ref` and `job_workflow_ref`
        # are not available in AWS trust policies. Tighter workflow scoping
        # requires a separate environment-scoped or custom-sub rollout.
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:pull_request"
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-github-actions-terraform-plan-pr"
    Component = "ecr"
  })
}

resource "aws_iam_policy" "terraform_plan_pr_read" {
  count = local.enable_terraform_plan_pr_role ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-terraform-plan-pr-read"
  description = "Dedicated read-only permissions for PR Terraform plans (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Read"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:GetEbsDefaultKmsKeyId",
          "ec2:GetEbsEncryptionByDefault",
          "ec2:GetManagedPrefixListEntries"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3MetadataRead"
        Effect = "Allow"
        Action = [
          "s3:GetAccelerateConfiguration",
          "s3:GetAccountPublicAccessBlock",
          "s3:GetAnalyticsConfiguration",
          "s3:GetBucket*",
          "s3:GetEncryptionConfiguration",
          "s3:GetIntelligentTieringConfiguration",
          "s3:GetInventoryConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetMetricsConfiguration",
          "s3:GetObjectLockConfiguration",
          "s3:GetPublicAccessBlock",
          "s3:GetReplicationConfiguration",
          "s3:GetStorageLensConfiguration",
          "s3:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ObjectRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject*"
        ]
        Resource = local.terraform_plan_pr_s3_object_arns
        Condition = {
          StringEquals = {
            "aws:ResourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "IAMRead"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Route53Read"
        Effect = "Allow"
        Action = [
          "route53:Get*",
          "route53:List*",
          "route53resolver:Get*",
          "route53resolver:List*",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchRead"
        Effect = "Allow"
        Action = [
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "EFSRead"
        Effect = "Allow"
        Action = [
          "elasticfilesystem:Describe*",
          "elasticfilesystem:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "LambdaRead"
        Effect = "Allow"
        Action = [
          "lambda:Get*",
          "lambda:List*"
        ]
        Resource = "*"
      },
      {
        # This Lambda has a distinct read-only handler and execution role. The
        # data source invokes with the explicit $LATEST qualifier, so IAM evaluates
        # this exact qualified ARN rather than the unqualified function ARN.
        # It is one of the exact semantic-read exceptions to the verb gate below.
        Sid      = "RelayIdentityStatusInvoke"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:$LATEST"]
      },
      {
        # The compute validator is a distinct GET-only handler and execution
        # role. Exact $LATEST qualification prevents this exception from
        # authorizing the stateful keygen function or a future alias/version.
        Sid      = "ComputeServerIdentityValidateInvoke"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator:$LATEST"]
      },
      {
        Sid    = "AutoScalingRead"
        Effect = "Allow"
        Action = [
          "autoscaling:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ELBRead"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMMetadataRead"
        Effect = "Allow"
        Action = [
          "ssm:Describe*",
          "ssm:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMParameterRead"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/*",
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/auth0/api-audience",
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/auth0/domain",
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/auth0/spa-client-id",
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/layerv/nhp/${var.environment}/*",
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.name_prefix}/*",
          # Shared registration keypair path; this intentionally has no
          # environment segment.
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/pool/*",
          "arn:aws:ssm:${local.region}::parameter/aws/service/canonical/ubuntu/*"
        ]
      },
      {
        Sid    = "SSMDocumentRead"
        Effect = "Allow"
        Action = [
          "ssm:GetDocument"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:document/${var.name_prefix}-*",
          "arn:aws:ssm:${local.region}:${local.account_id}:document/traefik-plugins-${var.environment}-*"
        ]
      },
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityServicesRead"
        Effect = "Allow"
        Action = [
          "guardduty:Get*",
          "guardduty:List*",
          "securityhub:Describe*",
          "securityhub:Get*",
          "securityhub:List*",
          "config:Describe*",
          "config:Get*",
          "config:List*"
        ]
        Resource = "*"
      },
      {
        # Some KMS metadata/list APIs are account-level and do not carry
        # aws:ResourceAccount. Keep IfExists here; decrypt below uses a strict
        # account match plus alias allowlist.
        Sid    = "KMSMetadataRead"
        Effect = "Allow"
        Action = [
          "kms:Describe*",
          "kms:Get*",
          "kms:List*"
        ]
        Resource = "*"
        Condition = {
          StringEqualsIfExists = {
            "aws:ResourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "KMSDecryptInAccount"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceAccount" = local.account_id
          }
          "ForAnyValue:StringLike" = {
            "kms:ResourceAliases" = [
              "alias/terraform-state",
              "alias/${var.name_prefix}-ebs",
              "alias/${var.name_prefix}-efs",
              "alias/${var.name_prefix}-secrets",
              "alias/${var.name_prefix}-logs",
              "alias/${var.name_prefix}-rds",
              "alias/${var.name_prefix}-cert"
            ]
          }
        }
      },
      {
        Sid    = "EventBridgeRead"
        Effect = "Allow"
        Action = [
          "events:Describe*",
          "events:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSRead"
        Effect = "Allow"
        Action = [
          "sns:Get*",
          "sns:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ACMRead"
        Effect = "Allow"
        Action = [
          "acm:Describe*",
          "acm:Get*",
          "acm:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ServiceDiscoveryRead"
        Effect = "Allow"
        Action = [
          "servicediscovery:Get*",
          "servicediscovery:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:Describe*",
          "secretsmanager:Get*"
        ]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"
      },
      {
        Sid    = "WAFRead"
        Effect = "Allow"
        Action = [
          "wafv2:Get*",
          "wafv2:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontRead"
        Effect = "Allow"
        Action = [
          "cloudfront:Get*",
          "cloudfront:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRRead"
        Effect = "Allow"
        Action = [
          "ecr:Describe*",
          "ecr:Get*",
          "ecr:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSRead"
        Effect = "Allow"
        Action = [
          "ecs:Describe*",
          "ecs:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBRead"
        Effect = "Allow"
        Action = [
          "dynamodb:Describe*",
          "dynamodb:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SQSRead"
        Effect = "Allow"
        Action = [
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ListQueueTags"
        ]
        Resource = "arn:aws:sqs:${local.region}:${local.account_id}:layerv-nhp-*"
      },
      {
        Sid    = "ElastiCacheRead"
        Effect = "Allow"
        Action = [
          "elasticache:Describe*",
          "elasticache:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "APIGatewayRead"
        Effect = "Allow"
        Action = [
          "apigateway:GET"
        ]
        Resource = "arn:aws:apigateway:${local.region}::/*"
      },
      {
        Sid    = "ChatbotRead"
        Effect = "Allow"
        Action = [
          "chatbot:Describe*",
          "chatbot:Get*",
          "chatbot:List*"
        ]
        Resource = "*"
      }
    ]
  })

  lifecycle {
    postcondition {
      # IAM rejects customer-managed policy documents above 6,144
      # non-whitespace characters. Because jsonencode emits no insignificant
      # whitespace, length(self.policy) equals AWS's quota-counted length and
      # catches regressions during plan instead of the post-merge apply.
      # Keep this policy document fully plan-known: introducing an apply-time
      # unknown would defer this postcondition to apply and lose the PR fence.
      # Split grants into another policy before they cross this fence.
      condition     = length(self.policy) <= 6144
      error_message = "terraform_plan_pr_read exceeds IAM's 6,144-character customer-managed policy quota; split statements into a dedicated policy before applying."
    }
  }
}

resource "aws_iam_role_policy_attachment" "terraform_plan_pr_read" {
  count = local.enable_terraform_plan_pr_role ? 1 : 0

  role       = aws_iam_role.github_actions_terraform_plan_pr[0].name
  policy_arn = aws_iam_policy.terraform_plan_pr_read[0].arn
}

# Terraform apply permissions - split into customer-managed policies
# Following AWS best practices: use managed policies instead of inline policies
# Part 1: EC2 and Networking
resource "aws_iam_policy" "terraform_apply_ec2" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-ec2"
  description = "EC2 and networking permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Write"
        Effect = "Allow"
        Action = [
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:ModifyLaunchTemplate",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteNetworkInterface",
          "ec2:AuthorizeSecurityGroup*",
          "ec2:RevokeSecurityGroup*",
          "ec2:ModifySecurityGroupRules",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:CreateVpcEndpoint",
          "ec2:DeleteVpcEndpoints",
          "ec2:ModifyVpcEndpoint",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "ELB"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:Create*",
          "elasticloadbalancing:Delete*",
          "elasticloadbalancing:Modify*",
          "elasticloadbalancing:Set*",
          "elasticloadbalancing:Register*",
          "elasticloadbalancing:Deregister*",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "AutoScaling"
        Effect = "Allow"
        Action = [
          "autoscaling:CreateAutoScalingGroup",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DeleteAutoScalingGroup",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:PutScalingPolicy",
          "autoscaling:DeletePolicy",
          "autoscaling:CreateOrUpdateTags",
          "autoscaling:DeleteTags",
          "autoscaling:AttachLoadBalancerTargetGroups",
          "autoscaling:DetachLoadBalancerTargetGroups",
          "autoscaling:PutLifecycleHook",
          "autoscaling:DeleteLifecycleHook",
          "autoscaling:EnableMetricsCollection",
          "autoscaling:DisableMetricsCollection"
        ]
        Resource = "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/layerv-nhp-*"
      },
      {
        # Required when creating ASGs that reference launch templates
        # ASG creation implicitly requires ec2:RunInstances to validate the launch template
        Sid    = "EC2RunInstancesForASG"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:aws:ec2:${local.region}:${local.account_id}:launch-template/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:volume/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:network-interface/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:subnet/*",
          "arn:aws:ec2:${local.region}::image/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_ec2" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_ec2.arn
}

# Dedicated, count-gated self-apply grant for the relay DMZ. Keeping this out of
# the broad always-present policies makes production (deploy_relay=false) retain
# an identical IAM document while sandbox can create the new boundary in one
# reviewed apply after the propagation shim in the root module.
resource "aws_iam_policy" "terraform_apply_relay_dmz" {
  count = var.deploy_relay_network ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-relay-dmz"
  description = "Relay DMZ network and Resolver permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RelayDmzVpcLifecycle"
        Effect = "Allow"
        Action = [
          "ec2:AcceptVpcPeeringConnection",
          "ec2:CreateFlowLogs",
          "ec2:CreateVpcPeeringConnection",
          "ec2:DeleteFlowLogs",
          "ec2:DeleteVpcPeeringConnection",
          "ec2:ModifyVpcPeeringConnectionOptions",
          "ec2:ReplaceRoute",
          "ec2:ReplaceRouteTableAssociation",
        ]
        Resource = "*"
      },
      {
        Sid    = "RelayDmzResolverLifecycle"
        Effect = "Allow"
        Action = [
          "route53resolver:AssociateFirewallRuleGroup",
          "route53resolver:AssociateResolverQueryLogConfig",
          "route53resolver:CreateFirewallDomainList",
          "route53resolver:CreateFirewallRule",
          "route53resolver:CreateFirewallRuleGroup",
          "route53resolver:CreateResolverQueryLogConfig",
          "route53resolver:DeleteFirewallDomainList",
          "route53resolver:DeleteFirewallRule",
          "route53resolver:DeleteFirewallRuleGroup",
          "route53resolver:DeleteResolverQueryLogConfig",
          "route53resolver:DisassociateFirewallRuleGroup",
          "route53resolver:DisassociateResolverQueryLogConfig",
          "route53resolver:GetFirewallConfig",
          "route53resolver:GetFirewallDomainList",
          "route53resolver:GetFirewallRuleGroup",
          "route53resolver:GetFirewallRuleGroupAssociation",
          "route53resolver:GetResolverQueryLogConfig",
          "route53resolver:GetResolverQueryLogConfigAssociation",
          "route53resolver:ListFirewallDomains",
          "route53resolver:ListFirewallRules",
          "route53resolver:ListTagsForResource",
          "route53resolver:TagResource",
          "route53resolver:UntagResource",
          "route53resolver:UpdateFirewallConfig",
          "route53resolver:UpdateFirewallDomains",
          "route53resolver:UpdateFirewallRule",
          "route53resolver:UpdateFirewallRuleGroupAssociation",
        ]
        Resource = "*"
      },
      {
        Sid      = "Route53ResolverServiceLinkedRole"
        Effect   = "Allow"
        Action   = "iam:CreateServiceLinkedRole"
        Resource = "arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/route53resolver.amazonaws.com/*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = "route53resolver.amazonaws.com"
          }
        }
      },
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-github-actions-relay-dmz"
    Component = "ecr"
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_relay_dmz" {
  count = var.deploy_relay_network ? 1 : 0

  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_relay_dmz[0].arn
}

# Part 2: IAM and Security
resource "aws_iam_policy" "terraform_apply_iam" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-iam"
  description = "IAM and security permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:UpdateAssumeRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:TagInstanceProfile",
          "iam:UntagInstanceProfile",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:PassRole",
          "iam:TagOpenIDConnectProvider",
          "iam:UntagOpenIDConnectProvider"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/layerv-nhp-*",
          "arn:aws:iam::${local.account_id}:role/nhp-*-github-actions",
          # The wildcard above anchors "-github-actions" at the ARN suffix;
          # it does not match the dedicated PR plan role's extra suffix.
          "arn:aws:iam::${local.account_id}:role/nhp-${var.environment}-github-actions-terraform-plan-pr",
          "arn:aws:iam::${local.account_id}:role/traefik-plugins-*",
          "arn:aws:iam::${local.account_id}:instance-profile/layerv-nhp-*",
          "arn:aws:iam::${local.account_id}:oidc-provider/*"
        ]
      },
      {
        Sid    = "IAMPolicies"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:TagPolicy",
          "iam:UntagPolicy"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:policy/nhp-*",
          "arn:aws:iam::${local.account_id}:policy/layerv-nhp-*"
        ]
      },
      {
        Sid    = "IAMUsers"
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:GetUser",
          "iam:TagUser",
          "iam:UntagUser",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:GetUserPolicy",
          "iam:ListUserPolicies",
          "iam:ListAccessKeys",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:user/layerv-nhp-*"
        ]
      },
      {
        # API Gateway v2 custom domains require a Service Linked Role on first use.
        # The SLR uses service principal ops.apigateway.amazonaws.com (NOT apigateway.amazonaws.com).
        Sid    = "ServiceLinkedRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateServiceLinkedRole"
        ]
        Resource = "arn:aws:iam::${local.account_id}:role/aws-service-role/ops.apigateway.amazonaws.com/*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = "ops.apigateway.amazonaws.com"
          }
        }
      },
      {
        Sid    = "SecurityServices"
        Effect = "Allow"
        Action = [
          "config:Delete*",
          "config:Put*",
          "config:Start*",
          "config:Stop*",
          "config:TagResource",
          "config:UntagResource",
          "guardduty:CreateDetector",
          "guardduty:DeleteDetector",
          "guardduty:TagResource",
          "guardduty:UntagResource",
          "guardduty:UpdateDetector",
          "securityhub:DisableImportFindingsForProduct",
          "securityhub:DisableSecurityHub",
          "securityhub:EnableImportFindingsForProduct",
          "securityhub:EnableSecurityHub",
          "wafv2:CreateWebACL",
          "wafv2:DeleteWebACL",
          "wafv2:UpdateWebACL",
          # Associate/Disassociate are required to attach the WebACL to the
          # bootstrap-alb ALB (regional resource). Create/Update/Delete alone
          # don't cover the association — prod apply hit AccessDenied on
          # wafv2:AssociateWebACL for bootstrap-alb-prod (run 26735323138).
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "wafv2:PutLoggingConfiguration",
          "wafv2:DeleteLoggingConfiguration",
          "wafv2:TagResource",
          "wafv2:UntagResource"
        ]
        Resource = "*"
      },
      {
        # SECURITY (#1125): same threat model as KMSDecryptInAccount /
        # KMSForEncryption — block mutating actions against keys owned by
        # other accounts (alias hijack, policy rewrite, schedule-delete).
        # Uses StringEqualsIfExists because kms:CreateKey is
        # non-resource-scoped (the key doesn't exist yet at request time);
        # IfExists permits it while still bounding the resource-scoped
        # actions (ScheduleKeyDeletion, EnableKeyRotation, *Alias, *Tag,
        # PutKeyPolicy) to in-account keys.
        #
        # kms:EnableKeyRotation is exercised at create time for any new
        # symmetric CMK with enable_key_rotation=true — the qURL v2 software-
        # custody envelope key (modules/kms, #3137) is the first such key added
        # since this statement was scoped. Pre-existing symmetric keys already
        # have rotation enabled in state, so TF never re-issues the call and the
        # gap stayed invisible until this key's create hit AccessDenied. The
        # same-apply grant+create races the IAM auth evaluator, so the envelope
        # key waits on time_sleep.qurl_v2_resource_key_envelope_iam_propagation
        # (terraform/main.tf). Read-side kms:GetKeyRotationStatus is already
        # covered by kms:Get* in the KMSDescribeInAccount statement above.
        Sid    = "KMS"
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
          "kms:EnableKeyRotation",
          "kms:ScheduleKeyDeletion",
          "kms:CreateAlias",
          "kms:DeleteAlias",
          "kms:UpdateAlias",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:PutKeyPolicy"
        ]
        Resource = "*"
        Condition = {
          StringEqualsIfExists = {
            "aws:ResourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_iam" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_iam.arn
}

# Part 3: Application Services
resource "aws_iam_policy" "terraform_apply_services" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-services"
  description = "Application services permissions for Terraform apply (${var.environment})"

  # Remove the legacy wildcard Route53 record grant only after the scoped
  # inline grants exist, avoiding a transient self-apply window where
  # Terraform loses Route53 record-write permission mid-run.
  depends_on = [
    aws_iam_role_policy.route53_managed_zone_record_changes,
    aws_iam_role_policy.route53_computed_zone_record_changes
  ]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # CreateHostedZone has no resource ARN and public hosted-zone
        # creation has no usable name/tag condition. Keep hosted-zone
        # lifecycle separate from record mutation so ChangeResourceRecordSets
        # can be scoped below to the environment-owned zones (#1146).
        # Residual risk: CI can still create undelegated public zones with
        # matching suffixes; revisit if Route53 adds tag/name conditions for
        # hosted-zone creation.
        Sid    = "Route53HostedZoneCreate"
        Effect = "Allow"
        Action = [
          "route53:CreateHostedZone"
        ]
        Resource = "*"
      },
      {
        # Hosted-zone lifecycle only. Route53 health-check tagging uses a
        # different ARN shape and needs its own grant if added later.
        Sid    = "Route53HostedZoneLifecycle"
        Effect = "Allow"
        Action = [
          "route53:DeleteHostedZone",
          "route53:ChangeTagsForResource"
        ]
        Resource = "arn:aws:route53:::hostedzone/*"
      },
      {
        Sid    = "CloudWatch"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:DeleteLogGroup",
          "logs:PutRetentionPolicy",
          "logs:AssociateKmsKey",
          "logs:DisassociateKmsKey",
          "logs:TagResource",
          "logs:UntagResource",
          # API Gateway v2 HTTP API access logging requires log delivery
          # and resource policy permissions on the caller
          "logs:CreateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
          # Log-metric filter for ServerPanic (PR #1098). ServerStartupEvent
          # moved to EMF in #1107 and no longer needs a filter resource,
          # but the panic filter remains because a panicking process
          # can't emit its own metric. TF manages the lifecycle end-to-
          # end, so all three verbs must be present: create/update,
          # delete on destroy, read on plan diff.
          "logs:PutMetricFilter",
          "logs:DeleteMetricFilter",
          "logs:DescribeMetricFilters",
          "cloudwatch:PutMetricAlarm",
          # PutCompositeAlarm: the canary-deployment module's canary_health
          # composite alarm (modules/canary-deployment/alarms.tf) needs this to
          # create/update. Its omission (PutMetricAlarm was granted, the composite
          # variant was not) silently broke EVERY sandbox apply with
          # `PutCompositeAlarm AccessDenied` once a change forced the alarm to
          # update. DeleteAlarms below already covers composite-alarm teardown.
          "cloudwatch:PutCompositeAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:PutDashboard",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid      = "CloudWatchPutMetricData"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = [
              "LayerV/NHP",
              "LayerV/NHP/Deploy",
              # Cross-repo: qurl-service #1163 emits SandboxLiveEnvLockFailure
              # from the shared-sandbox premerge gate through this role.
              "LayerV/QURLServiceCI",
              "NHP/BlueGreen"
            ]
          }
        }
      },
      {
        Sid    = "SNSChatbot"
        Effect = "Allow"
        Action = [
          "sns:CreateTopic",
          "sns:DeleteTopic",
          "sns:SetTopicAttributes",
          "sns:TagResource",
          "sns:UntagResource",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sns:Publish",
          "chatbot:CreateSlackChannelConfiguration",
          "chatbot:UpdateSlackChannelConfiguration",
          "chatbot:DeleteSlackChannelConfiguration",
          "chatbot:TagResource",
          "chatbot:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:CancelRotateSecret",
          "secretsmanager:TagResource",
          "secretsmanager:UntagResource"
        ]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"
      },
      {
        Sid      = "SecretsManagerRandomPassword"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetRandomPassword"]
        Resource = "*"
      },
      {
        Sid    = "EFS"
        Effect = "Allow"
        Action = [
          "elasticfilesystem:CreateFileSystem",
          "elasticfilesystem:DeleteFileSystem",
          "elasticfilesystem:CreateMountTarget",
          "elasticfilesystem:DeleteMountTarget",
          "elasticfilesystem:CreateAccessPoint",
          "elasticfilesystem:DeleteAccessPoint",
          "elasticfilesystem:Put*",
          "elasticfilesystem:TagResource",
          "elasticfilesystem:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "ServiceDiscovery"
        Effect = "Allow"
        Action = [
          "servicediscovery:CreatePrivateDnsNamespace",
          "servicediscovery:DeleteNamespace",
          "servicediscovery:CreateService",
          "servicediscovery:DeleteService",
          "servicediscovery:UpdateService",
          "servicediscovery:TagResource",
          "servicediscovery:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Buckets"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:PutBucketVersioning",
          "s3:PutEncryptionConfiguration",
          "s3:GetEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          # `aws_s3_bucket_ownership_controls.{alb_access_logs,athena_query_results}`
          # in `modules/bootstrap-alb/access_logs.tf` requires
          # `s3:PutBucketOwnershipControls`. Missing this is what failed nhp
          # run 26251713769 — #2071 added the bucket prefix to Resource but
          # didn't add this action. AWS ALB access-log delivery requires the
          # bucket be `BucketOwnerEnforced`, so the ownership-controls failure
          # cascades into the ALB modify-attributes AccessDenied.
          # `GetBucketOwnershipControls` is covered by `terraform_read.S3Read`
          # (`s3:Get*` on `*`); only the Put is needed here. No
          # `s3:DeleteBucketOwnershipControls` — mirrors `S3QURLLinkBucket`
          # precedent; sandbox destroy isn't in CI today.
          "s3:PutBucketOwnershipControls",
          "s3:PutBucketTagging",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:GetBucketNotification",
          "s3:PutBucketNotification",
          "s3:PutLifecycleConfiguration",
          "s3:GetLifecycleConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::layerv-nhp-*",
          "arn:aws:s3:::traefik-plugins-*",
          # bootstrap-alb access-log + Athena query-results buckets
          # (`bootstrap-alb-alb-logs-<env>-<account>` and
          # `bootstrap-alb-athena-<env>-<account>`). Naming-shape
          # coupling is called out in
          # `terraform/modules/bootstrap-alb/access_logs.tf` and
          # `terraform/modules/bootstrap-alb/main.tf::local.project`.
          # Renaming `local.project` in that module away from
          # `bootstrap-alb` requires updating this allowlist in lockstep.
          "arn:aws:s3:::bootstrap-alb-*"
        ]
      },
      {
        # S3 object permissions for Terraform-managed objects (plugin manifests, configs)
        Sid    = "S3Objects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObjectTagging",
          "s3:PutObjectTagging"
        ]
        Resource = "arn:aws:s3:::layerv-nhp-*-plugins/*"
      },
      {
        Sid    = "EventBridge"
        Effect = "Allow"
        Action = [
          "events:PutRule",
          "events:DeleteRule",
          "events:PutTargets",
          "events:RemoveTargets",
          "events:EnableRule",
          "events:DisableRule",
          "events:TagResource",
          "events:UntagResource"
        ]
        Resource = "arn:aws:events:${local.region}:${local.account_id}:rule/layerv-nhp-*"
      },
      {
        Sid    = "SQS"
        Effect = "Allow"
        Action = [
          "sqs:CreateQueue",
          "sqs:DeleteQueue",
          "sqs:GetQueueAttributes",
          "sqs:SetQueueAttributes",
          "sqs:TagQueue",
          "sqs:UntagQueue",
          "sqs:GetQueueUrl",
          "sqs:ListQueueTags"
        ]
        Resource = "arn:aws:sqs:${local.region}:${local.account_id}:layerv-nhp-*"
      },
      {
        # API Gateway v2 (HTTP API) for status page
        Sid    = "APIGatewayV2"
        Effect = "Allow"
        Action = [
          "apigateway:POST",
          "apigateway:GET",
          "apigateway:PATCH",
          "apigateway:DELETE",
          "apigateway:PUT",
          "apigateway:TagResource",
          "apigateway:UntagResource"
        ]
        # Resource uses /* because API Gateway tag ARNs contain URL-encoded
        # sub-ARNs (e.g., /tags/arn%3Aaws%3Aapigateway%3A...%2Fv2%2Fapis%2F*)
        # which don't match narrower /tags/* patterns in IAM evaluation.
        Resource = "arn:aws:apigateway:${local.region}::/*"
      },
      {
        # S3 object permissions for status page frontend (index.html upload)
        Sid    = "S3StatusPage"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObjectTagging",
          "s3:PutObjectTagging"
        ]
        Resource = "arn:aws:s3:::layerv-nhp-*-status-page-*/*"
      },
      {
        # ECR lifecycle and repository policy management for terraform-managed repos.
        #
        # CreateRepository is scoped to the `layerv/` namespace so this role can
        # add new repos to `local.ecr_repos` without out-of-band manual bootstrap.
        # Matches the rest of `terraform_apply_services` (terraform-apply-equivalent
        # within the env). Apply ordering: `aws_ecr_repository.main` declares
        # `depends_on` on this attachment so the new perm is in place before any
        # CreateRepository call. See blast-radius comment in
        # `terraform/variables.tf::qurl_reverse_tunnel_server_github_repo` for the
        # threat model on the role's overall scope.
        Sid    = "ECRManagement"
        Effect = "Allow"
        Action = [
          "ecr:CreateRepository",
          "ecr:PutLifecyclePolicy",
          "ecr:DeleteLifecyclePolicy",
          "ecr:SetRepositoryPolicy",
          "ecr:DeleteRepositoryPolicy",
          "ecr:TagResource",
          "ecr:UntagResource"
        ]
        Resource = "arn:aws:ecr:${local.region}:${local.account_id}:repository/layerv/*"
      },
      {
        # ECS infrastructure management for terraform-managed resources
        # Note: ecs:RegisterTaskDefinition and ecs:DeregisterTaskDefinition require Resource="*"
        # per AWS API requirements (task definitions cannot be scoped by ARN at registration time)
        Sid    = "ECSInfrastructure"
        Effect = "Allow"
        Action = [
          "ecs:CreateCluster",
          "ecs:DeleteCluster",
          "ecs:UpdateCluster",
          "ecs:CreateService",
          "ecs:DeleteService",
          "ecs:UpdateService",
          "ecs:RegisterTaskDefinition",
          "ecs:DeregisterTaskDefinition",
          "ecs:TagResource",
          "ecs:UntagResource"
        ]
        Resource = "*"
      },
      {
        # Step Functions — Terraform management of canary state machines
        Sid    = "StepFunctions"
        Effect = "Allow"
        Action = [
          "states:CreateStateMachine",
          "states:DeleteStateMachine",
          "states:UpdateStateMachine",
          "states:DescribeStateMachine",
          "states:ListStateMachineVersions",
          "states:TagResource",
          "states:UntagResource",
          "states:ListTagsForResource"
        ]
        Resource = "arn:aws:states:${local.region}:${local.account_id}:stateMachine:layerv-nhp-*"
      },
      {
        # Step Functions — canary deploy runtime (start and monitor executions)
        Sid    = "StepFunctionsExecution"
        Effect = "Allow"
        Action = [
          "states:StartExecution",
          "states:DescribeExecution"
        ]
        Resource = [
          "arn:aws:states:${local.region}:${local.account_id}:stateMachine:layerv-nhp-*",
          "arn:aws:states:${local.region}:${local.account_id}:execution:layerv-nhp-*:*"
        ]
      }
    ]
  })

  lifecycle {
    postcondition {
      # IAM rejects customer-managed policy documents above 6,144
      # non-whitespace characters. Because jsonencode emits no insignificant
      # whitespace, length(self.policy) equals AWS's quota-counted length and
      # catches regressions during plan instead of the post-merge apply.
      # Keep this policy document fully plan-known: introducing an apply-time
      # unknown would defer this postcondition to apply and lose the PR fence.
      # The current 5,602-character document intentionally leaves only 542
      # characters: the next substantial grant must split into another policy.
      # At current prod inputs the next-largest sibling is terraform_apply_iam
      # at 2,679 characters (3,465 headroom), so only services merits a guard.
      condition     = length(self.policy) <= 6144
      error_message = "terraform_apply_services exceeds IAM's 6,144-character customer-managed policy quota; split statements into a dedicated policy before applying."
    }
  }
}

resource "aws_iam_role_policy" "route53_managed_zone_record_changes" {
  count = length(local.route53_change_record_hosted_zone_arns) > 0 ? 1 : 0

  name = "route53-managed-zone-record-changes"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Route53ManagedZoneRecordChanges"
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets"
        ]
        Resource = local.route53_change_record_hosted_zone_arns
      }
    ]
  })
}

resource "aws_iam_role_policy" "route53_computed_zone_record_changes" {
  count = length(var.route53_change_record_name_patterns) > 0 ? 1 : 0

  name = "route53-computed-zone-record-changes"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Terraform-created hosted zones, such as the qurl-service private
        # hosted zone, do not have a stable zone ID before apply. Keep this
        # wildcard resource constrained by Route53's normalized-record-name
        # condition so it cannot write arbitrary records into orphan zones.
        # This relies on Route53 rejecting record names outside the target
        # zone's suffix, so the allowed names must stay fully qualified to an
        # environment-owned suffix.
        Sid    = "Route53ComputedZoneRecordChanges"
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets"
        ]
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          # Route53 populates this multi-valued key for every
          # ChangeResourceRecordSets batch; ForAllValues is the documented
          # shape for validating every record in a multi-record request.
          # ForAllValues is vacuously true if AWS omits the key, so the
          # Null=false guard below keeps the wildcard zone ARN fail-closed.
          "ForAllValues:StringLike" = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = var.route53_change_record_name_patterns
          }
          Null = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_services" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_services.arn
}

# Part 3b: Agent-registration email OTP (SES v2)
#
# Keep this separate from terraform_apply_services. Adding these actions to
# that already-large policy exceeded IAM's 6,144-character managed-policy
# quota in sandbox run 29138466833, so Terraform could not create a new policy
# version and the entire deploy stopped before SES was touched.
# When enabled this is the ninth managed-policy attachment on today's prod role
# (AWS defaults to 10 per role), leaving one default slot. Dark environments do
# not create or attach it.
# check-terraform-iam-coverage.py counts the shared module's worst-case bindings
# and fails above 10. Filling the last slot exhausts the runway; any subsequent
# split must consolidate grants or deliberately raise both the account quota
# and the checked limit.
resource "aws_iam_policy" "terraform_apply_ses" {
  count = var.agent_otp_ses_enabled ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-terraform-apply-ses"
  description = "SES permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The apply role needs SES v2 create/update/delete on the sender
        # identity, its MAIL FROM attributes, and the configuration set + event
        # destination (terraform/agent_otp_ses.tf), plus the read verbs used by
        # Terraform refresh. Several SES identity/configuration-set APIs do not
        # support resource-level permissions, so this account/region-scoped
        # control plane grant must use Resource="*".
        Sid    = "SESAgentOTP"
        Effect = "Allow"
        Action = [
          "ses:CreateEmailIdentity",
          "ses:DeleteEmailIdentity",
          "ses:GetEmailIdentity",
          "ses:PutEmailIdentityDkimSigningAttributes",
          "ses:PutEmailIdentityMailFromAttributes",
          "ses:PutEmailIdentityConfigurationSetAttributes",
          "ses:CreateConfigurationSet",
          "ses:DeleteConfigurationSet",
          "ses:GetConfigurationSet",
          "ses:PutConfigurationSetDeliveryOptions",
          "ses:PutConfigurationSetReputationOptions",
          "ses:PutConfigurationSetSendingOptions",
          "ses:CreateConfigurationSetEventDestination",
          "ses:UpdateConfigurationSetEventDestination",
          "ses:DeleteConfigurationSetEventDestination",
          "ses:GetConfigurationSetEventDestinations",
          # Classic SES inbound receipt-rule control for the private sandbox
          # qurl-go OTP mailbox. The same dedicated policy already carries the
          # SES sender-plane grants and has ample document-size headroom.
          "ses:CreateReceiptRuleSet",
          "ses:DescribeReceiptRuleSet",
          "ses:DeleteReceiptRuleSet",
          "ses:CreateReceiptRule",
          "ses:DescribeReceiptRule",
          "ses:SetReceiptRulePosition",
          "ses:UpdateReceiptRule",
          "ses:DeleteReceiptRule",
          "ses:DescribeActiveReceiptRuleSet",
          "ses:SetActiveReceiptRuleSet",
          "ses:TagResource",
          "ses:UntagResource",
          "ses:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })

  # Unlike terraform_apply_services, this dedicated document is far below the
  # 6,144-character ceiling. Keep the plan-time size guard on the policy that
  # is actually near the quota rather than duplicating a vacuous invariant.
}

resource "aws_iam_role_policy_attachment" "terraform_apply_ses" {
  count = var.agent_otp_ses_enabled ? 1 : 0

  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_ses[0].arn
}

# Part 4: Data Services (DynamoDB, RDS, Lambda, SSM, ACM)
resource "aws_iam_policy" "terraform_apply_data" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-data"
  description = "Data services permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBTables"
        Effect = "Allow"
        Action = [
          "dynamodb:CreateTable",
          "dynamodb:DeleteTable",
          "dynamodb:UpdateTable",
          "dynamodb:UpdateTimeToLive",
          "dynamodb:UpdateContinuousBackups",
          "dynamodb:TagResource",
          "dynamodb:UntagResource",
          # Item-level operations for aws_dynamodb_table_item resources
          # and terraform_data provisioners (e.g., seeding smoke test customer tier)
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-*"
      },
      {
        # KMS permissions for DynamoDB/RDS encryption with customer-managed keys
        # CreateGrant is required when creating DynamoDB tables with CMK encryption
        # SECURITY (#1125): condition uses aws:ResourceAccount (not
        # kms:CallerAccount) so it actually blocks cross-account KMS use —
        # see KMSDecryptInAccount in the terraform_read policy above for
        # the full rationale.
        Sid    = "KMSForEncryption"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "SSMACMLambda"
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:DeleteParameter",
          "ssm:CreateDocument",
          "ssm:UpdateDocument",
          "ssm:DeleteDocument",
          "ssm:UpdateDocumentDefaultVersion",
          "ssm:CreateAssociation",
          "ssm:UpdateAssociation",
          "ssm:DeleteAssociation",
          "ssm:DescribeAssociation",
          "ssm:AddTagsToResource",
          "ssm:RemoveTagsFromResource",
          "acm:RequestCertificate",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "acm:RemoveTagsFromCertificate",
          "lambda:CreateFunction",
          "lambda:DeleteFunction",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:PutFunctionConcurrency",
          "lambda:DeleteFunctionConcurrency",
          "lambda:PutFunctionEventInvokeConfig",
          "lambda:UpdateFunctionEventInvokeConfig",
          "lambda:DeleteFunctionEventInvokeConfig",
          # Connector Authority runtime slice: Terraform manages the closed
          # blue/green aliases and the steady provisioned-concurrency config on
          # each hub function. These are MANAGEMENT actions (create/update/delete/
          # read) only -- NOT lambda:InvokeFunction, which stays fenced to the
          # exact helper ARNs in TerraformHelperInvoke so the apply role can never
          # invoke an Authority alias.
          # An image change on an Authority function is only half-applied
          # without this: update_function_code moves $LATEST, but the blue/green
          # aliases resolve to immutable published versions, so Terraform must
          # publish a new version before it can repoint them. Without it an
          # apply leaves $LATEST on the new digest while both aliases -- the
          # actual serving path -- stay on the old one, and the apply fails
          # mid-transition. Observed on control-update-apply run 30218341432.
          # Publishing a version is a MANAGEMENT action over code Terraform has
          # already been authorized to update; it grants no new invoke rights,
          # and lambda:InvokeFunction stays fenced to the exact helper ARNs in
          # TerraformHelperInvoke.
          "lambda:PublishVersion",
          "lambda:CreateAlias",
          "lambda:UpdateAlias",
          "lambda:DeleteAlias",
          "lambda:GetAlias",
          "lambda:PutProvisionedConcurrencyConfig",
          "lambda:DeleteProvisionedConcurrencyConfig",
          "lambda:GetProvisionedConcurrencyConfig",
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:TagResource",
          "lambda:UntagResource",
          "cloudtrail:CreateTrail",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:StartLogging",
          "cloudtrail:StopLogging",
          "cloudtrail:AddTags",
          "cloudtrail:RemoveTags",
          "cloudtrail:PutEventSelectors"
        ]
        Resource = "*"
      },
      {
        # Terraform invokes exactly these six unqualified helper functions to
        # seed/read infrastructure state. The sixth (control-hub-keygen) seeds the
        # Connector Hub key-material secret in-account at apply (slice 5b), so no
        # key ever enters tfstate. Connector Authority aliases (ca-ia/ra/icr) are
        # runtime capabilities invoked by the Hub worker, NOT deploy helpers, and
        # must never enter the shared apply role.
        Sid    = "TerraformHelperInvoke"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-keygen",
          "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-ac-keygen",
          "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-etcd-tls-gen",
          "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-registration-keygen",
          "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-keygen",
          "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-control-hub-keygen",
          # aws_lambda_invocation sends Qualifier=$LATEST, and IAM treats the
          # qualified and unqualified function ARNs as DIFFERENT resources, so
          # the bare ARN above does not authorize that call. The Hub identity
          # seeding invocation failed on exactly this
          # (control-update-apply run 30220858809: AccessDeniedException on
          # ...:function:layerv-nhp-sandbox-control-hub-keygen:$LATEST), which
          # left the Hub identity parameter stuck at its pending-keygen
          # placeholder. Same trap terraform/CLAUDE.md already records for the
          # relay-status invocation data source. Pinning $LATEST explicitly
          # keeps this exact-ARN rather than widening to a wildcard qualifier.
          "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-control-hub-keygen:$LATEST",
        ]
      },
      {
        # Post-deploy validation invoke (NOT a Terraform operation): the
        # "Deploy Sandbox - Validate" integration test
        # (tests/integration/acme_cert_test.go::TestACMECertLambdaCheckStatus)
        # invokes this read-only cert-status function under the deploy role
        # after apply with no Qualifier — grant the exact UNqualified ARN, never
        # :$LATEST. It belongs on this apply policy, not the terraform_read
        # refresh slot; scope is fenced in check-terraform-iam-coverage.py.
        Sid      = "AcmeCertManagerStatusInvoke"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-acme-cert-manager"]
      },
      {
        Sid    = "LambdaLayer"
        Effect = "Allow"
        Action = [
          "lambda:PublishLayerVersion",
          "lambda:DeleteLayerVersion"
        ]
        Resource = "arn:aws:lambda:${local.region}:${local.account_id}:layer:layerv-nhp-*"
      },
      {
        Sid    = "ElastiCache"
        Effect = "Allow"
        Action = [
          "elasticache:CreateServerlessCache",
          "elasticache:DeleteServerlessCache",
          "elasticache:ModifyServerlessCache",
          "elasticache:DescribeServerlessCaches",
          "elasticache:ListTagsForResource",
          "elasticache:AddTagsToResource",
          "elasticache:RemoveTagsFromResource",
          "elasticache:CreateCacheSubnetGroup",
          "elasticache:DeleteCacheSubnetGroup",
          "elasticache:ModifyCacheSubnetGroup",
          "elasticache:DescribeCacheSubnetGroups"
        ]
        Resource = [
          "arn:aws:elasticache:${local.region}:${local.account_id}:serverlesscache:layerv-nhp-*",
          "arn:aws:elasticache:${local.region}:${local.account_id}:subnetgroup:layerv-nhp-*"
        ]
      },
      {
        # CreateServerlessCache and ModifyServerlessCache independently
        # authorize a referenced user group. Keep that dependent-resource
        # grant to the one exact dark Control group.
        Sid    = "ElastiCacheControlCacheUserGroupDependency"
        Effect = "Allow"
        Action = [
          "elasticache:CreateServerlessCache",
          "elasticache:ModifyServerlessCache"
        ]
        Resource = "arn:aws:elasticache:${local.region}:${local.account_id}:usergroup:layerv-nhp-${var.environment}-control-otp-users"
      },
      {
        # These are the only ElastiCache users/groups in the repository. Keep
        # the shared apply role inside this environment's global authority
        # namespace; Create/ModifyUserGroup requires both user and usergroup
        # resource types according to the ElastiCache IAM action contract.
        Sid    = "ElastiCacheControlRBAC"
        Effect = "Allow"
        Action = [
          "elasticache:CreateUser",
          "elasticache:ModifyUser",
          "elasticache:DeleteUser",
          "elasticache:DescribeUsers",
          "elasticache:CreateUserGroup",
          "elasticache:ModifyUserGroup",
          "elasticache:DeleteUserGroup",
          "elasticache:DescribeUserGroups",
          "elasticache:ListTagsForResource",
          "elasticache:AddTagsToResource",
          "elasticache:RemoveTagsFromResource"
        ]
        Resource = [
          "arn:aws:elasticache:${local.region}:${local.account_id}:user:layerv-nhp-${var.environment}-control-*",
          "arn:aws:elasticache:${local.region}:${local.account_id}:usergroup:layerv-nhp-${var.environment}-control-*"
        ]
      }
    ]
  })

  lifecycle {
    postcondition {
      # IAM counts non-whitespace characters toward the 6,144-character
      # customer-managed-policy quota. jsonencode emits no insignificant
      # whitespace, so this is the exact provider payload length. Environment-
      # specific renders measured 3,529/3,517 characters in sandbox/production
      # after adding the acme cert-status invoke, leaving
      # 2,615/2,627 characters below the hard quota.
      condition     = length(self.policy) <= 6144
      error_message = "terraform_apply_data exceeds IAM's 6,144-character customer-managed policy quota; split statements within the existing attachment budget before applying."
    }
  }
}

resource "aws_iam_role_policy_attachment" "terraform_apply_data" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_data.arn
}

# Region pinned to us-east-1 because the website CDK app always deploys
# there regardless of nhp's region — the data source uses
# provider = aws.us_east_1 for the same reason. Reconciles the manual
# incident-2026-04-24-cfn-describe-website-api inline grant from the
# prod release incident (#1323); the manual inline is tracked for
# deletion in #1415 (the two grants overlap until then — IAM
# allow-union is fine but leaves attribution ambiguous in CloudTrail).
#
# Gated on website_api_cfn_stack_name alone — narrower than the
# data source's local.website_api_dns_enabled (which also requires
# deploy_website_api_dns / website_api_domain / qurl_hosted_zone_id).
# Keying off the stack-name variable maps cleanly to "the role needs
# this permission" and avoids drift if the data source's gate later
# adds another input. The root precondition at terraform/main.tf:994
# enforces the four inputs travel together for prod plans, so the
# practical state space is unchanged.
resource "aws_iam_role_policy" "cloudformation_website_api" {
  count = var.website_api_cfn_stack_name == null ? 0 : 1

  name = "cloudformation-website-api"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WebsiteAPIStackRead"
        Effect = "Allow"
        Action = [
          "cloudformation:DescribeStacks",
          "cloudformation:GetTemplate"
        ]
        Resource = "arn:aws:cloudformation:us-east-1:${local.account_id}:stack/${var.website_api_cfn_stack_name}/*"
      }
    ]
  })
}

# S3 write permissions for Traefik plugins bucket
# Allows traefik-plugins repo to upload plugins to S3
resource "aws_iam_policy" "plugin_bucket_write" {
  count = var.enable_plugin_bucket_policy ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-plugin-bucket-write"
  description = "S3 plugin bucket write permissions (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PluginBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.plugin_bucket_arn,
          "${var.plugin_bucket_arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "plugin_bucket_write" {
  count = var.enable_plugin_bucket_policy ? 1 : 0

  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.plugin_bucket_write[0].arn
}

# ECS deployment permissions for QURL service
# Allows CI to register task definitions and update ECS services
#
# Wildcard usage explanation:
# - ECSTaskDefinition uses Resource="*" because AWS requires it for ecs:RegisterTaskDefinition
#   (task definitions cannot be scoped by ARN at registration time)
# - ECSServiceDeploy uses "layerv-nhp-*-qurl-api" pattern to allow deployment across
#   environments (sandbox, prod) from the same policy
# - PassRoleForECS uses similar wildcard pattern for execution/task roles
resource "aws_iam_policy" "qurl_ecs_deploy" {
  count = var.deploy_qurl_ecr ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-qurl-ecs-deploy"
  description = "ECS deployment permissions for QURL service (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Note: Resource="*" is required by AWS for ecs:RegisterTaskDefinition
        Sid    = "ECSTaskDefinition"
        Effect = "Allow"
        Action = [
          "ecs:RegisterTaskDefinition",
          "ecs:DescribeTaskDefinition",
          "ecs:DeregisterTaskDefinition"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSServiceDeploy"
        Effect = "Allow"
        Action = [
          "ecs:UpdateService",
          "ecs:DescribeServices",
          "ecs:DescribeClusters"
        ]
        Resource = [
          "arn:aws:ecs:${local.region}:${local.account_id}:cluster/layerv-nhp-*-qurl-api",
          "arn:aws:ecs:${local.region}:${local.account_id}:service/layerv-nhp-*-qurl-api/*"
        ]
      },
      {
        Sid    = "PassRoleForECS"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          "arn:aws:iam::${local.account_id}:role/layerv-nhp-*-qurl-api-*"
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "qurl_ecs_deploy" {
  count = var.deploy_qurl_ecr ? 1 : 0

  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.qurl_ecs_deploy[0].arn
}

# Static site permissions (QURL Link)
# Allows CI to create/manage CloudFront distributions and S3 buckets for static sites:
# - qurl.link redirect page
#
# Wildcard usage explanation:
# - CloudFront uses Resource="*" because CloudFront resources are global and distribution
#   ARNs are not known at policy creation time. Actions are scoped to specific operations.
# - S3 bucket ARNs use wildcard patterns to support multiple environments (sandbox, prod).
# - ACM uses Resource="*" with region condition because certificate ARNs are not known
#   at policy creation time, but is scoped to us-east-1 (CloudFront requirement).
resource "aws_iam_policy" "qurl_link_static" {
  name        = "nhp-${var.environment}-github-actions-qurl-link"
  description = "CloudFront and S3 permissions for QURL link redirect page (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudFrontDistribution"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateDistribution",
          "cloudfront:GetDistribution",
          "cloudfront:GetDistributionConfig",
          "cloudfront:UpdateDistribution",
          "cloudfront:DeleteDistribution",
          "cloudfront:TagResource",
          "cloudfront:UntagResource",
          "cloudfront:ListTagsForResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontOriginAccessControl"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateOriginAccessControl",
          "cloudfront:GetOriginAccessControl",
          "cloudfront:UpdateOriginAccessControl",
          "cloudfront:DeleteOriginAccessControl",
          "cloudfront:ListOriginAccessControls"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontResponseHeadersPolicy"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateResponseHeadersPolicy",
          "cloudfront:GetResponseHeadersPolicy",
          "cloudfront:UpdateResponseHeadersPolicy",
          "cloudfront:DeleteResponseHeadersPolicy",
          "cloudfront:ListResponseHeadersPolicies"
        ]
        Resource = "*"
      },
      {
        # Distribution-level real-time metrics subscription. Required by
        # `aws_cloudfront_monitoring_subscription.qurl_resolve` (PR #1795).
        Sid    = "CloudFrontMonitoringSubscription"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateMonitoringSubscription",
          "cloudfront:GetMonitoringSubscription",
          "cloudfront:DeleteMonitoringSubscription"
        ]
        Resource = "*"
      },
      {
        # CloudFront standard logging (v2) for the resolve distribution's access
        # logs (issue #1799) — delivery source/destination management. These
        # resources have deterministic, author-chosen names, so the grant is
        # resource-scoped (us-east-1 because CF vended-logs delivery is managed
        # there; account from local.account_id). The Get*/List* read path is
        # covered by `terraform_read`'s CloudWatchRead Sid (`logs:Get*`/`List*`
        # on `*`), so only writes live here.
        #
        # v2 (not legacy `logging_config`) is deliberate: the resolve edge
        # carries the access token in the `?token=` query string during the
        # GET->POST migration, so it is redacted from both the WAF logs and the
        # server's Gin logs. Legacy CF logging has no field selection and would
        # write `cs-uri-query` unredacted; v2's `record_fields` lets us drop
        # `cs-uri-query` while still capturing `x-edge-detailed-result-type`.
        #
        # The inline `tags` on the source/destination apply via `logs:TagResource`
        # / `logs:UntagResource`, which `terraform_apply_services`' CloudWatch Sid
        # already grants on `Resource = "*"` (same github_actions role) — that's a
        # pre-existing grant, so it neither races this apply nor needs repeating
        # here. The only freshly-granted verbs (the Put*/Delete* below) are what
        # the propagation shim covers.
        Sid    = "CloudFrontStandardLoggingV2Endpoints"
        Effect = "Allow"
        Action = [
          "logs:PutDeliverySource",
          "logs:DeleteDeliverySource",
          "logs:PutDeliveryDestination",
          "logs:DeleteDeliveryDestination"
        ]
        Resource = [
          "arn:aws:logs:us-east-1:${local.account_id}:delivery-source:layerv-nhp-*-qurl-resolve",
          "arn:aws:logs:us-east-1:${local.account_id}:delivery-destination:layerv-nhp-*-qurl-resolve-s3"
        ]
      },
      {
        # The delivery itself (links source -> destination). `CreateDelivery`
        # mints an AWS-generated delivery ID, so the delivery ARN can't be
        # predicted at policy-author time — these three stay on `Resource = "*"`.
        # Same single-distribution blast-radius trade-off as the CloudFront
        # statements above. The delivery resources depend_on the existing
        # `time_sleep.qurl_link_static_iam_propagation` shim — but note that shim
        # is 60s (action-list-edit calibration), whereas the Endpoints grant adds
        # *new resource-prefix ARN targets*, which per terraform/CLAUDE.md (#2072)
        # can take ~180s. We reuse the 60s shim rather than add a dedicated 180s
        # one (attended, sandbox-first rollout); the prod-rollout ledger documents
        # the expected first-apply AccessDenied + re-run, esp. for the prod promote.
        Sid    = "CloudFrontStandardLoggingV2Delivery"
        Effect = "Allow"
        Action = [
          "logs:CreateDelivery",
          "logs:UpdateDeliveryConfiguration",
          "logs:DeleteDelivery"
        ]
        Resource = "*"
      },
      {
        # `PutDeliverySource` (the `aws_cloudwatch_log_delivery_source.qurl_resolve`
        # create, root main.tf) passes the resolve distribution's ARN as the
        # source `resource_arn`. CloudWatch vended-logs evaluates a *cross-service*
        # authorization on that source resource: the calling principal must hold
        # `cloudfront:AllowVendedLogDeliveryForResource` on the distribution, in
        # ADDITION to `logs:PutDeliverySource` (granted in the Endpoints Sid above).
        # The S3 *destination* side needs no identity twin of this — it is
        # authorized by the bucket's resource policy (the
        # `delivery.logs.amazonaws.com` grant on `aws_s3_bucket.qurl_resolve_logs`),
        # which Terraform manages directly. So this CloudFront action is the only
        # cross-service grant the delivery chain needs. Omitting it was the gap that
        # red-balled the first post-#2437 apply (PutDeliverySource AccessDenied on
        # exactly this action — a missing grant, not a propagation race, so re-runs
        # never cleared it).
        #
        # Resource = "*" is deliberate, and for a sharper reason than the
        # bootstrap-circularity rationale on the sibling CloudFront Sids: a blanket
        # `*` grant propagates through the IAM evaluator well inside the 60s
        # `qurl_link_static_iam_propagation` shim the delivery source depends_on,
        # whereas a resource-prefix ARN (`arn:aws:cloudfront::${acct}:distribution/*`)
        # is exactly the freshly-scoped-prefix case terraform/CLAUDE.md flags as
        # needing ~180s — which the 60s shim would NOT cover, re-introducing the red.
        # The action is CloudFront-distribution-scoped regardless, and the resolve
        # distribution's ID is AWS-generated (unknown at policy-author time, and not
        # visible to this module), so `*` is both narrower than it looks and the only
        # workable scope here.
        Sid      = "CloudFrontVendedLogDelivery"
        Effect   = "Allow"
        Action   = ["cloudfront:AllowVendedLogDeliveryForResource"]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontCachePolicy"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateCachePolicy",
          "cloudfront:DeleteCachePolicy",
          "cloudfront:GetCachePolicy",
          "cloudfront:ListCachePolicies",
          "cloudfront:UpdateCachePolicy"
        ]
        Resource = "*"
      },
      {
        # Required by `terraform_data.qurl_link_invalidation` (root):
        # invalidates /index.html on every content edit so a deploy isn't
        # racing the 1h cache_control TTL. GetInvalidation is needed by
        # `aws cloudfront wait invalidation-completed` which polls until
        # propagation finishes.
        #
        # Resource = "*": this policy is attached to the CI role at
        # bootstrap, before any CloudFront distribution exists, so a
        # tight resource-scoped ARN would chicken-and-egg the greenfield
        # apply. Matches the surrounding CloudFront statements'
        # bootstrap-circularity rationale; blast radius is "CI role can
        # invalidate any distribution it can resolve" which is
        # acceptable for a single-distribution module.
        Sid    = "CloudFrontInvalidation"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateInvalidation",
          "cloudfront:GetInvalidation"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3QURLLinkBucket"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:GetBucketAcl",
          "s3:PutBucketAcl",
          "s3:GetBucketCORS",
          "s3:PutBucketCORS",
          "s3:GetBucketWebsite",
          "s3:PutBucketWebsite",
          "s3:DeleteBucketWebsite",
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketOwnershipControls",
          "s3:PutBucketOwnershipControls",
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging",
          "s3:GetBucketLogging",
          "s3:PutBucketLogging",
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObjectTagging",
          "s3:PutObjectTagging",
          "s3:DeleteObjectTagging"
        ]
        Resource = [
          "arn:aws:s3:::layerv-nhp-*-qurl-link",
          "arn:aws:s3:::layerv-nhp-*-qurl-link/*"
        ]
      },
      {
        # Resolve access-logs bucket object cleanup, so `terraform` can empty it
        # under `force_destroy = true` when enable_resolve_access_logs is turned
        # off or the resolve edge is torn down (issue #1799) — a path that runs
        # in CI on a promote with run_terraform=true. Bucket
        # create/encrypt/lifecycle/policy perms already come from the generic
        # `layerv-nhp-*` S3Buckets statement in terraform-apply-services; only
        # the object list+delete verbs for force_destroy are missing there.
        # force_destroy empties via the ListObjectVersions API (s3:ListBucketVersions)
        # even on a never-versioned bucket and issues version-aware deletes, so
        # both *Versions verbs are required alongside the unversioned pair, or the
        # documented rollback hits AccessDenied while emptying. Scoped to the logs bucket.
        Sid    = "S3QURLResolveLogsCleanup"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:ListBucketVersions",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = [
          "arn:aws:s3:::layerv-nhp-*-qurl-resolve-logs",
          "arn:aws:s3:::layerv-nhp-*-qurl-resolve-logs/*"
        ]
      },
      {
        # bootstrap-alb bucket object cleanup, so `terraform` can empty the
        # access-log and Athena buckets under `force_destroy = true` during the
        # sandbox bootstrap-ALB retirement. Same shape and same reason as
        # `S3QURLResolveLogsCleanup` above: the generic `bootstrap-alb-*`
        # entry in the S3Buckets statement carries bucket-level verbs only, so
        # force_destroy hits AccessDenied while emptying. Both *Versions verbs
        # are required — force_destroy enumerates via ListObjectVersions and
        # issues version-aware deletes even on a never-versioned bucket, and the
        # access-log bucket IS versioned.
        #
        # Deliberately scoped to SANDBOX buckets. Production bootstrap forensics
        # are irrecoverable and its module is not being retired, so CI must not
        # be able to empty them — this mirrors in IAM the same protection
        # `lifecycle { prevent_destroy = true }` gives in Terraform. A future
        # production retirement should widen this in its own reviewed change,
        # not inherit the grant from sandbox's.
        Sid    = "S3BootstrapAlbSandboxCleanup"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:ListBucketVersions",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = [
          "arn:aws:s3:::bootstrap-alb-alb-logs-sandbox-*",
          "arn:aws:s3:::bootstrap-alb-alb-logs-sandbox-*/*",
          "arn:aws:s3:::bootstrap-alb-athena-sandbox-*",
          "arn:aws:s3:::bootstrap-alb-athena-sandbox-*/*"
        ]
      },
      {
        # ACM certificates for CloudFront must be in us-east-1
        Sid    = "ACMUsEast1"
        Effect = "Allow"
        Action = [
          "acm:RequestCertificate",
          "acm:DescribeCertificate",
          "acm:DeleteCertificate",
          "acm:ListCertificates",
          "acm:ListTagsForCertificate",
          "acm:AddTagsToCertificate"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "us-east-1"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "qurl_link_static" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.qurl_link_static.arn
}

# ============================================================================
# Smoke Test Policy
#
# nhp/tests/smoke mostly reuses the existing permissions already attached
# to aws_iam_role.github_actions. Every API call the Tier 1/2 tests make
# is covered by:
#
#   - terraform_read:      ec2:Describe*, autoscaling:Describe*,
#                          elasticloadbalancing:Describe*,
#                          cloudwatch:Describe*/Get*/List*,
#                          ssm:Describe*/Get*/List*,
#                          secretsmanager:Get* (scoped layerv-nhp-*)
#   - context_lookups_relay_ssm: ssm:SendCommand + ssm:GetCommandInvocation
#                               (relay-enabled sandbox: exact AWS-RunShellScript,
#                               same-account Environment=sandbox instances, and
#                               the unavoidable action-only invocation read)
#   - SSMACMLambda:        ssm:PutParameter (for M2M token cache)
#   - terraform_apply_*:   cloudwatch:PutMetricData (for smoke metric)
#
# Tier 1/3 smoke tests use CloudWatch Logs Insights, which requires
# actions not granted by the broad CloudWatchRead statement
# (Describe/Get/List/FilterLogEvents/StartLiveTail). The policy below
# grants those actions narrowly: StartQuery is scoped to the per-log-group
# ARNs the smoke suite queries (nhp-server cell0 log group + AC log group);
# GetQueryResults/StopQuery operate on query IDs (not resources) so remain
# unscoped.
#
# When a new smoke test introduces a query against a log group not listed
# below, extend the StartQuery Resource list — do NOT widen to "*".
# When a new smoke test needs a brand-new action, add another dedicated
# aws_iam_role_policy scoped to just that action — do not recreate the
# broad smoke_test_read policy this block replaces.
# ============================================================================

resource "aws_iam_role_policy" "smoke_test_cwl_insights" {
  name = "smoke-test-cwl-insights"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StartInsightsQueryOnNHPLogGroups"
        Effect = "Allow"
        Action = ["logs:StartQuery"]
        Resource = [
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/layerv/nhp/${var.environment}/cell0/server:*",
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/layerv/nhp/${var.environment}/ac:*",
        ]
      },
      {
        Sid      = "ReadAndStopInsightsQuery"
        Effect   = "Allow"
        Action   = ["logs:GetQueryResults", "logs:StopQuery"]
        Resource = "*"
      },
    ]
  })
}

# ============================================================================
# OUTPUTS - Unified interface regardless of primary/secondary account
# ============================================================================
#
# When replication is enabled, secondary accounts pull from their own local
# registry (images are replicated from primary). When replication is disabled,
# secondary accounts pull cross-account from the primary registry (legacy).
#
# The local.secondary_ecr_account_id helper used below is defined alongside
# the rest of the module locals near the top of this file.
# ============================================================================

output "server_repo_url" {
  description = "NHP Server ECR repository URL"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-server"].repository_url : "${local.secondary_ecr_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-server"
}

output "server_repo_arn" {
  description = "NHP Server ECR repository ARN"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-server"].arn : "arn:aws:ecr:${local.region}:${local.secondary_ecr_account_id}:repository/layerv/nhp-server"
}

output "relay_repo_url" {
  description = "NHP Relay ECR repository URL (#2208)"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-relay"].repository_url : "${local.secondary_ecr_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-relay"
}

output "relay_repo_arn" {
  description = "NHP Relay ECR repository ARN (#2208)"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-relay"].arn : "arn:aws:ecr:${local.region}:${local.secondary_ecr_account_id}:repository/layerv/nhp-relay"
}

output "ac_repo_url" {
  description = "NHP AC ECR repository URL"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-ac"].repository_url : "${local.secondary_ecr_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-ac"
}

output "ac_repo_arn" {
  description = "NHP AC ECR repository ARN"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-ac"].arn : "arn:aws:ecr:${local.region}:${local.secondary_ecr_account_id}:repository/layerv/nhp-ac"
}

output "github_actions_role_arn" {
  description = "GitHub Actions IAM role ARN"
  value       = aws_iam_role.github_actions.arn
}

output "github_actions_role_name" {
  description = "GitHub Actions IAM role name"
  value       = aws_iam_role.github_actions.name
}

output "github_actions_terraform_plan_pr_role_arn" {
  description = "Sandbox-only read-only IAM role ARN for terraform-plan-pr.yml. Store in GitHub Actions repo secret AWS_TERRAFORM_PLAN_PR_ROLE_ARN."
  value       = try(aws_iam_role.github_actions_terraform_plan_pr[0].arn, null)
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC provider ARN (created or referenced from existing)"
  value       = local.oidc_provider_arn
}

output "qurl_repo_url" {
  description = "QURL Service ECR repository URL"
  value       = var.deploy_qurl_ecr && var.is_primary_account ? aws_ecr_repository.main["nhp-qurl"].repository_url : var.deploy_qurl_ecr ? "${local.secondary_ecr_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-qurl" : null
}

output "qurl_repo_arn" {
  description = "QURL Service ECR repository ARN"
  value       = var.deploy_qurl_ecr && var.is_primary_account ? aws_ecr_repository.main["nhp-qurl"].arn : var.deploy_qurl_ecr ? "arn:aws:ecr:${local.region}:${local.secondary_ecr_account_id}:repository/layerv/nhp-qurl" : null
}

# Scanner Lambda ECR repo (`layerv/qurl-scanner-lambda`).
#
# Mirrors the `qurl_repo_*` shape above so the consumer surface is symmetric.
# Threaded into `module.qurl_service` (root main.tf) as inputs that feed:
#   - `aws_lambda_function.qurl_scanner.image_uri = "<url>:<tag>"`
#   - a `terraform_data` shim whose `input = <arn>` lets the scanner SSM
#     image-tag param `depends_on` the repo creation. Without this, an
#     apply that lands the SSM param before the repo trips qurl-service
#     CI's `exists=true → push → fails` branch on the next main push.
output "qurl_scanner_lambda_repo_url" {
  description = "QURL scanner Lambda ECR repository URL (consumed by the scanner Lambda's image_uri)."
  value       = var.deploy_qurl_ecr && var.is_primary_account ? aws_ecr_repository.main["qurl-scanner-lambda"].repository_url : var.deploy_qurl_ecr ? "${local.secondary_ecr_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/qurl-scanner-lambda" : null
}

output "qurl_scanner_lambda_repo_arn" {
  description = "QURL scanner Lambda ECR repository ARN (consumed by the scanner module's terraform_data shim to manufacture a depends_on edge from the SSM image-tag param to the repo)."
  value       = var.deploy_qurl_ecr && var.is_primary_account ? aws_ecr_repository.main["qurl-scanner-lambda"].arn : var.deploy_qurl_ecr ? "arn:aws:ecr:${local.region}:${local.secondary_ecr_account_id}:repository/layerv/qurl-scanner-lambda" : null
}

output "repository_names" {
  description = "Fully qualified ECR repo names with `layerv/` prefix; empty on secondary accounts."
  # Computed from `local.ecr_repos` rather than `aws_ecr_repository.main[r].name`
  # so the value is plan-time-known. Consumers using this in `for_each`
  # (e.g. the per-repo replication-failure alarms in
  # `terraform/ecr_replication_check.tf`) need the keys at plan time, and
  # a resource attribute would be `(known after apply)` on a greenfield
  # bootstrap. The literal pattern matches the resource name format at
  # `aws_ecr_repository.main` (line ~295: `name = "layerv/${each.key}"`);
  # the precondition below locks them in lockstep so a future format
  # change can't silently desync the two sites.
  precondition {
    condition = !var.is_primary_account || alltrue([
      for r in local.ecr_repos :
      aws_ecr_repository.main[r].name == "layerv/${r}"
    ])
    error_message = "ECR repository name format has diverged from `layerv/<repo>` — the literal pattern in this output's value is now stale. Update both `aws_ecr_repository.main.name` and this output's `value` together."
  }
  # Uniqueness fence on `local.ecr_repos`. The static list is trivially
  # injective today, but a future change that derives the list from a
  # variable concat (e.g. `concat(core, var.extra_repos)`) could
  # introduce a duplicate that would silently collapse `for_each` keys
  # downstream — including the per-repo failure-count alarms in
  # `terraform/ecr_replication_check.tf`. Catches the collision at
  # plan time rather than at apply.
  precondition {
    condition     = length(distinct(local.ecr_repos)) == length(local.ecr_repos)
    error_message = "ECR repo names in `local.ecr_repos` collide: ${jsonencode(local.ecr_repos)}. A duplicate would silently collapse `for_each` keys on every consumer. De-dup the list (or its source variables) before re-applying."
  }
  value = var.is_primary_account ? [for r in local.ecr_repos : "layerv/${r}"] : []
}

output "repository_arns" {
  description = "ECR repo ARNs in 1:1 order with `repository_names`; empty on secondary accounts."
  value       = var.is_primary_account ? [for r in local.ecr_repos : aws_ecr_repository.main[r].arn] : []
}

output "is_replication_source" {
  description = "True iff this account is the primary AND replication is configured outbound."
  # Shared with `aws_ecr_replication_configuration.cross_account.count`
  # via `local.is_replication_source`, so the output and the resource
  # gate are mechanically in lockstep — a future broadening of the
  # gate (e.g., adding `var.replication_paused`) only has to update
  # the local declaration above.
  value = local.is_replication_source
}

output "untagged_expiry_hours" {
  description = "Untagged-image lifecycle expiry in hours; consumed by the replication-check Lambda's lookback fence."
  value       = local.ecr_untagged_expiry_days * 24
}

# Trigger sources for `time_sleep.qurl_link_static_iam_propagation` —
# see that resource in `terraform/main.tf` for the rationale.
output "qurl_link_static_policy_doc_hash" {
  description = "sha256 of the qurl_link_static CI policy doc; trigger source for IAM-propagation shims."
  value       = sha256(aws_iam_policy.qurl_link_static.policy)
}

output "qurl_link_static_policy_arn" {
  description = "ARN of the qurl_link_static CI policy."
  value       = aws_iam_policy.qurl_link_static.arn
}

output "qurl_link_static_attachment_id" {
  description = "ID of the role-policy attachment for qurl_link_static. Use as a trigger source so an IAM-propagation `time_sleep` orders after the attachment lands at AWS — the implicit dep on the doc/arn outputs only orders against the policy resource, not the attachment that actually feeds the auth evaluator."
  value       = aws_iam_role_policy_attachment.qurl_link_static.id
}

# Trigger sources for `time_sleep.bootstrap_alb_iam_propagation` —
# see that resource in `terraform/main.tf` for the rationale. Mirror
# of the qurl_link_static_* triplet above; same pattern.
output "terraform_apply_services_policy_doc_hash" {
  description = "sha256 of the terraform-apply-services CI policy doc; trigger source for IAM-propagation shims when adding bucket-prefix scopes or other resource-shaped grants."
  value       = sha256(aws_iam_policy.terraform_apply_services.policy)
}

output "terraform_apply_services_policy_arn" {
  description = "ARN of the terraform-apply-services CI policy. Catches the rename-via-`name` case in IAM-propagation shim triggers."
  value       = aws_iam_policy.terraform_apply_services.arn
}

output "terraform_apply_services_attachment_id" {
  description = "ID of the role-policy attachment for terraform-apply-services. Forces a `time_sleep` shim to order AFTER the attachment lands at AWS — see qurl_link_static_attachment_id above for the same shape."
  value       = aws_iam_role_policy_attachment.terraform_apply_services.id
}

# Trigger sources for `time_sleep.agent_otp_ses_iam_propagation` in the root
# module. The SES resources are created by the same apply that first creates and
# attaches this policy, so they must wait for the IAM evaluator to observe it.
output "terraform_apply_ses_policy_doc_hash" {
  description = "sha256 of the terraform-apply-ses CI policy doc; trigger source for the agent-OTP SES IAM-propagation shim."
  value       = var.agent_otp_ses_enabled ? sha256(aws_iam_policy.terraform_apply_ses[0].policy) : null
}

output "terraform_apply_ses_policy_arn" {
  description = "ARN of the terraform-apply-ses CI policy."
  value       = var.agent_otp_ses_enabled ? aws_iam_policy.terraform_apply_ses[0].arn : null
}

output "terraform_apply_ses_attachment_id" {
  description = "ID of the role-policy attachment for terraform-apply-ses; orders SES creation after the grant is attached."
  value       = var.agent_otp_ses_enabled ? aws_iam_role_policy_attachment.terraform_apply_ses[0].id : null
}

output "terraform_apply_relay_dmz_policy_doc_hash" {
  description = "sha256 of the count-gated relay-DMZ self-apply policy, or empty when the relay network is disabled."
  value       = var.deploy_relay_network ? sha256(aws_iam_policy.terraform_apply_relay_dmz[0].policy) : ""
}

output "terraform_apply_relay_dmz_policy_arn" {
  description = "ARN of the relay-DMZ self-apply policy, or empty when disabled."
  value       = var.deploy_relay_network ? aws_iam_policy.terraform_apply_relay_dmz[0].arn : ""
}

output "terraform_apply_relay_dmz_attachment_id" {
  description = "Attachment ID used to order the relay-DMZ IAM propagation wait after the policy reaches the apply role."
  value       = var.deploy_relay_network ? aws_iam_role_policy_attachment.terraform_apply_relay_dmz[0].id : ""
}

# Trigger sources for `time_sleep.qurl_v2_resource_key_envelope_iam_propagation`
# — see that resource in `terraform/main.tf`. Same triplet shape as
# terraform_apply_services above; this is the policy that carries the KMS
# key-management grant (Sid "KMS"), whose kms:EnableKeyRotation action the qURL
# v2 envelope CMK's create needs freshly propagated.
output "terraform_apply_iam_policy_doc_hash" {
  description = "sha256 of the terraform-apply-iam CI policy doc; trigger source for the envelope-CMK EnableKeyRotation IAM-propagation shim."
  value       = sha256(aws_iam_policy.terraform_apply_iam.policy)
}

output "terraform_apply_iam_policy_arn" {
  description = "ARN of the terraform-apply-iam CI policy. Catches the rename-via-`name` case in IAM-propagation shim triggers."
  value       = aws_iam_policy.terraform_apply_iam.arn
}

output "terraform_apply_iam_attachment_id" {
  description = "ID of the role-policy attachment for terraform-apply-iam. Forces a `time_sleep` shim to order AFTER the attachment lands at AWS — see qurl_link_static_attachment_id above for the same shape."
  value       = aws_iam_role_policy_attachment.terraform_apply_iam.id
}

# Trigger sources for Route53 record-change IAM propagation shims. The inline
# policies below replace the legacy wildcard record-mutation grant; same-account
# DNS writers wait on each active policy's content and inline-policy ID before
# cutover writes. Omit inactive policy families so prod cross-account zones do
# not carry inert managed-zone triggers.
output "route53_record_change_policy_triggers" {
  description = "Trigger map for Route53 record-change IAM propagation shims."
  value = merge(
    length(aws_iam_role_policy.route53_managed_zone_record_changes) > 0 ? {
      managed_policy_doc_hash = sha256(join("", aws_iam_role_policy.route53_managed_zone_record_changes[*].policy))
      managed_policy_id       = join(",", aws_iam_role_policy.route53_managed_zone_record_changes[*].id)
    } : {},
    length(aws_iam_role_policy.route53_computed_zone_record_changes) > 0 ? {
      computed_policy_doc_hash = sha256(join("", aws_iam_role_policy.route53_computed_zone_record_changes[*].policy))
      computed_policy_id       = join(",", aws_iam_role_policy.route53_computed_zone_record_changes[*].id)
    } : {},
  )
}

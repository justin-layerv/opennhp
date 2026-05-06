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
  core_ecr_repos = ["nhp-server", "nhp-ac", "nhp-console"]
  ecr_repos      = var.deploy_qurl_ecr ? concat(local.core_ecr_repos, ["nhp-qurl"]) : local.core_ecr_repos

  # Single source of truth for "this account is the source of cross-
  # account ECR replication." Referenced by both
  # `aws_ecr_replication_configuration.cross_account.count` and the
  # `is_replication_source` output, so the two stay in mechanical
  # lockstep — a future change (e.g., adding a `var.replication_paused`
  # flag to the gate) only has to update this local. Replaces the
  # earlier output-precondition assertion approach.
  is_replication_source = var.is_primary_account && var.enable_replication && length(var.secondary_account_ids) > 0

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

  # Cross-account ECR policy (shared across repos)
  # Note: secondary_account_ids should be passed from tfvars for cross-account pull
  ecr_cross_account_policy = length(var.secondary_account_ids) > 0 ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
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
    }]
  }) : null

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
}

resource "aws_ecr_lifecycle_policy" "main" {
  for_each = var.is_primary_account ? toset(local.ecr_repos) : []

  repository = aws_ecr_repository.main[each.key].name
  policy     = local.ecr_lifecycle_policy
}

# Cross-account pull policy (allows specific accounts to pull).
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
  for_each = var.is_primary_account && length(var.secondary_account_ids) > 0 ? toset(local.ecr_repos) : []

  repository = aws_ecr_repository.main[each.key].name
  policy     = local.ecr_cross_account_policy
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
    Statement = [
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

  policy = jsonencode({
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
          "autoscaling:CancelInstanceRefresh"
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
        Action = [
          "route53:Get*",
          "route53:List*"
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
}

resource "aws_iam_role_policy_attachment" "terraform_read" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_read.arn
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
        # actions (ScheduleKeyDeletion, *Alias, *Tag, PutKeyPolicy) to
        # in-account keys.
        Sid    = "KMS"
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
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

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Route53"
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:CreateHostedZone",
          "route53:DeleteHostedZone",
          "route53:ChangeTagsForResource"
        ]
        Resource = "*"
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
          "cloudwatch:PutMetricData",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:PutDashboard",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource"
        ]
        Resource = "*"
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
          "s3:PutBucketTagging",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:PutLifecycleConfiguration",
          "s3:GetLifecycleConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::layerv-nhp-*",
          "arn:aws:s3:::traefik-plugins-*"
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
        # ECR lifecycle and repository policy management for terraform-managed repos
        Sid    = "ECRManagement"
        Effect = "Allow"
        Action = [
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
}

resource "aws_iam_role_policy_attachment" "terraform_apply_services" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_services.arn
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
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:TagResource",
          "lambda:UntagResource",
          "lambda:InvokeFunction",
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
      }
    ]
  })
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
#   - context_lookups:     ssm:SendCommand + ssm:GetCommandInvocation
#                          (scoped AWS-RunShellScript + instance ARNs)
#   - SSMACMLambda:        ssm:PutParameter (for M2M token cache)
#   - terraform_apply_*:   cloudwatch:PutMetricData (for smoke metric)
#
# Tier 3 (22_server_logs_test.go) uses CloudWatch Logs Insights, which
# requires actions not granted by the broad CloudWatchRead statement
# (Describe/Get/List/FilterLogEvents/StartLiveTail). The policy below
# grants those actions narrowly: StartQuery is scoped to the nhp-server
# log group ARN; GetQueryResults/StopQuery operate on query IDs (not
# resources) so remain unscoped.
#
# If a future test introduces another new action, add another dedicated
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
        Sid      = "StartInsightsQueryOnNHPServerLogGroup"
        Effect   = "Allow"
        Action   = ["logs:StartQuery"]
        Resource = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/layerv/nhp/${var.environment}/cell0/server:*"]
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

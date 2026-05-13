# Traefik Plugins Deploy Module
#
# Out-of-band deployment infrastructure for Traefik plugins on AC instances.
# Creates a dedicated GitHub Actions IAM role, S3 deploy bucket, SSM documents
# (deploy + rollback), and CloudWatch log group for SSM command output.
#
# This role is SEPARATE from the NHP CI role (nhp-{env}-github-actions) —
# it's used exclusively by the traefik-plugins repo.
#
# Resources:
# - IAM role: traefik-plugins-{env}-github-actions (OIDC trust for traefik-plugins repo)
# - S3 bucket: traefik-plugins-deploy-{account_id} (plugin tarballs staged for SSM deploy)
# - SSM document: traefik-plugins-{env}-deploy-plugin (download/extract/health-check/rollback)
# - SSM document: traefik-plugins-{env}-rollback-plugin (restore from backup)
# - CloudWatch log group: /aws/ssm/traefik-plugins-{env}/deploy

locals {
  account_id = var.aws_account_id
  region     = var.aws_region

  role_name         = "traefik-plugins-${var.environment}-github-actions"
  deploy_bucket     = "traefik-plugins-deploy-${var.aws_account_id}"
  deploy_doc_name   = "traefik-plugins-${var.environment}-deploy-plugin"
  rollback_doc_name = "traefik-plugins-${var.environment}-rollback-plugin"

  # GitHub Environment name in the deploy workflow's `environment:` directive
  # (https://github.com/layervai/traefik-plugins/blob/main/.github/workflows/deploy.yml).
  # The map IS the allow-list — Terraform fails with "Invalid index" at plan
  # time if a future PR adds a new value to var.environment's validation
  # without updating this map. A workflow-side rename is out of band and
  # tracked at traefik-plugins#99.
  github_environment_by_env = {
    sandbox = "sandbox"
    prod    = "production"
  }
  github_environment_name = local.github_environment_by_env[var.environment]

  module_tags = merge(var.tags, {
    Component = "traefik-plugins-deploy"
  })
}

# ==================== IAM Role ====================

resource "aws_iam_role" "github_actions" {
  name        = local.role_name
  description = "GitHub Actions role for ${var.github_org}/${var.github_repo} (${var.environment})"

  # SECURITY (#1125, same threat model as #1121): the `sub` is pinned to
  # the single GH-Environment-scoped token this per-env workflow emits.
  # The previous `repo:<owner>/<repo>:*` wildcard accepted PR-event
  # tokens — a malicious PR could have assumed the role unmerged.
  # Per-env scoping (via `local.github_environment_name`) also blocks
  # cross-env assumption: a sandbox token cannot assume the prod role,
  # which the previous shape relied on workflow-side pinning to enforce.
  # Intentionally tighter than the broader nhp role's redundant
  # `traefik_plugins_github_repo` entries (`terraform/modules/ecr/main.tf`);
  # retiring those is tracked in #1522.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = var.github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:environment:${local.github_environment_name}"
        }
      }
    }]
  })

  tags = merge(local.module_tags, {
    Name    = local.role_name
    Project = "traefik-plugins"
  })
}

# Inline policy: github-actions-policy
# Broad Terraform management permissions for the traefik-plugins repo's own infra.
# Preserved from existing sandbox role for import compatibility.
# TODO: Prune unused statements once imports are stable — the traefik-plugins repo
# does not currently run Terraform, so IAMRoles, IAMOIDCProvider, CloudWatchAlarms,
# CloudWatchDashboards, and SSMAssociations are aspirational. The deploy-policy
# below is what the workflow actually uses at runtime.
resource "aws_iam_role_policy" "github_actions" {
  name = "github-actions-policy"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3DeployBucket"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:PutBucketPolicy",
          "s3:GetBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutEncryptionConfiguration",
          "s3:GetEncryptionConfiguration",
          "s3:PutBucketTagging",
          "s3:GetBucketTagging",
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          "s3:PutLifecycleConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketAcl",
          "s3:GetBucketCors",
          "s3:PutBucketCors",
          "s3:GetBucketWebsite",
          "s3:GetBucketLocation",
          "s3:GetBucketLogging",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetBucketOwnershipControls",
          "s3:GetBucketRequestPayment",
          "s3:GetReplicationConfiguration",
          "s3:GetAccelerateConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::traefik-plugins-*",
          "arn:aws:s3:::traefik-plugins-*/*"
        ]
      },
      {
        Sid    = "S3TerraformState"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = var.terraform_state_bucket != "" ? [
          "arn:aws:s3:::${var.terraform_state_bucket}",
          "arn:aws:s3:::${var.terraform_state_bucket}/*"
        ] : ["arn:aws:s3:::placeholder-no-state-bucket"]
      },
      {
        Sid    = "DynamoDBStateLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = [
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.terraform_lock_table}"
        ]
      },
      {
        Sid    = "SSMDocuments"
        Effect = "Allow"
        Action = [
          "ssm:CreateDocument",
          "ssm:UpdateDocument",
          "ssm:DeleteDocument",
          "ssm:DescribeDocument",
          "ssm:GetDocument",
          "ssm:UpdateDocumentDefaultVersion",
          "ssm:AddTagsToResource",
          "ssm:RemoveTagsFromResource",
          "ssm:ListTagsForResource",
          "ssm:DescribeDocumentPermission"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:document/traefik-plugins-*"
        ]
      },
      {
        Sid    = "SSMSendCommand"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:document/traefik-plugins-*",
          "arn:aws:ssm:${local.region}:${local.account_id}:document/AWS-RunShellScript",
          "arn:aws:ssm:${local.region}::document/AWS-RunShellScript"
        ]
      },
      {
        Sid    = "SSMSendCommandInstances"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand"
        ]
        Resource = [
          "arn:aws:ec2:${local.region}:${local.account_id}:instance/*"
        ]
        Condition = {
          StringEquals = {
            "ssm:resourceTag/Name" = var.ac_instance_tag_names
          }
        }
      },
      {
        Sid    = "SSMCommandStatus"
        Effect = "Allow"
        Action = [
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Describe"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMOIDCProvider"
        Effect = "Allow"
        Action = [
          "iam:CreateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider",
          "iam:TagOpenIDConnectProvider",
          "iam:UntagOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProviderThumbprint"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"
        ]
      },
      {
        Sid    = "IAMRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PassRole",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:ListInstanceProfilesForRole"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/traefik-plugins-*",
          "arn:aws:iam::${local.account_id}:instance-profile/traefik-plugins-*"
        ]
      },
      {
        Sid    = "CloudWatchAlarms"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource",
          "cloudwatch:ListTagsForResource"
        ]
        Resource = [
          "arn:aws:cloudwatch:${local.region}:${local.account_id}:alarm:traefik-plugins-*"
        ]
      },
      {
        Sid    = "CloudWatchDashboards"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutDashboard",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListDashboards"
        ]
        Resource = [
          "arn:aws:cloudwatch::${local.account_id}:dashboard/traefik-plugins-*"
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:DeleteLogGroup",
          "logs:PutRetentionPolicy",
          "logs:TagLogGroup",
          "logs:UntagLogGroup",
          "logs:ListTagsLogGroup",
          "logs:TagResource",
          "logs:ListTagsForResource"
        ]
        Resource = [
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/ssm/traefik-plugins-*",
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/ssm/traefik-plugins-*:*"
        ]
      },
      {
        Sid    = "CloudWatchLogsDescribe"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMAssociations"
        Effect = "Allow"
        Action = [
          "ssm:CreateAssociation",
          "ssm:DeleteAssociation",
          "ssm:DescribeAssociation",
          "ssm:UpdateAssociation",
          "ssm:ListTagsForResource",
          "ssm:AddTagsToResource",
          "ssm:RemoveTagsFromResource"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:association/*",
          "arn:aws:ssm:${local.region}:${local.account_id}:document/traefik-plugins-*",
          "arn:aws:ec2:${local.region}:${local.account_id}:instance/*"
        ]
      }
    ]
  })
}

# Inline policy: traefik-plugins-{env}-deploy-policy
# Runtime deploy/rollback permissions: S3 access, SSM SendCommand, EC2 describe.
resource "aws_iam_role_policy" "deploy" {
  name = "traefik-plugins-${var.environment}-deploy-policy"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.deploy.arn,
          "${aws_s3_bucket.deploy.arn}/*"
        ]
      },
      {
        Sid    = "S3BootTimePlugins"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.boot_time_plugins_bucket_arn,
          "${var.boot_time_plugins_bucket_arn}/*"
        ]
      },
      ],
      # KMS permissions for boot-time plugins bucket (when bucket uses KMS encryption)
      var.boot_time_plugins_kms_key_arn != null ? [{
        Sid    = "KMSBootTimePlugins"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = [var.boot_time_plugins_kms_key_arn]
      }] : [],
      [{
        Sid    = "SSMSendCommandDocuments"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:document/${local.deploy_doc_name}",
          "arn:aws:ssm:${local.region}:${local.account_id}:document/${local.rollback_doc_name}",
          "arn:aws:ssm:${local.region}:${local.account_id}:document/AWS-RunShellScript",
          "arn:aws:ssm:${local.region}::document/AWS-RunShellScript"
        ]
        },
        {
          Sid    = "SSMSendCommandInstances"
          Effect = "Allow"
          Action = [
            "ssm:SendCommand"
          ]
          Resource = [
            "arn:aws:ec2:${local.region}:${local.account_id}:instance/*"
          ]
          Condition = {
            StringEquals = {
              "ssm:resourceTag/Name" = var.ac_instance_tag_names
            }
          }
        },
        {
          Sid    = "SSMCommandStatus"
          Effect = "Allow"
          Action = [
            "ssm:GetCommandInvocation",
            "ssm:ListCommandInvocations"
          ]
          Resource = "*"
        },
        {
          Sid    = "EC2DescribeInstances"
          Effect = "Allow"
          Action = [
            "ec2:DescribeInstances",
            "ec2:DescribeTags"
          ]
          Resource = "*"
        },
        {
          # Lets the deploy workflow filter discovered AC instances by ASG
          # LifecycleState (InService) so we don't SSM-deploy onto instances
          # mid-refresh whose user-data hasn't installed the AWS CLI yet.
          Sid    = "AutoScalingDescribeInstances"
          Effect = "Allow"
          Action = [
            "autoscaling:DescribeAutoScalingInstances"
          ]
          Resource = "*"
        }
    ])
  })
}

# ==================== S3 Deploy Bucket ====================

resource "aws_s3_bucket" "deploy" {
  bucket = local.deploy_bucket

  tags = merge(local.module_tags, {
    Name    = local.deploy_bucket
    Project = "traefik-plugins"
    Purpose = "Traefik plugin deployment staging"
  })
}

resource "aws_s3_bucket_versioning" "deploy" {
  bucket = aws_s3_bucket.deploy.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "deploy" {
  bucket = aws_s3_bucket.deploy.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "deploy" {
  bucket = aws_s3_bucket.deploy.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "deploy" {
  bucket = aws_s3_bucket.deploy.id

  rule {
    id     = "cleanup-old-versions"
    status = "Enabled"

    filter {
      prefix = "traefik-plugins/"
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ==================== SSM Documents ====================

resource "aws_ssm_document" "deploy" {
  name            = local.deploy_doc_name
  document_type   = "Command"
  document_format = "YAML"

  content = <<-YAML
    schemaVersion: '2.2'
    description: 'Deploy Traefik plugin from S3 with health checks and rollback support'
    parameters:
      Version:
        type: String
        description: "Version/commit SHA to deploy"
      S3Bucket:
        type: String
        description: "S3 bucket containing the plugin tarball"
      PluginName:
        type: String
        default: "qurl-router"
        description: "Plugin name used for S3 tarball key (e.g. qurl-router)"
      DeployPath:
        type: String
        default: "/home/ubuntu/traefik/plugins-local/src/github.com/traefik/qurl-router"
        description: "Path to deploy the plugin"
      BackupRetention:
        type: String
        default: "3"
        description: "Number of backups to retain"
    mainSteps:
      - action: aws:runShellScript
        name: deployPlugin
        inputs:
          runCommand:
            - |
              #!/bin/bash
                  # Deploy Traefik plugin from S3
                  # SSM Parameters: Version, S3Bucket, DeployPath, BackupRetention
                  set -e

                  # Ensure snap binaries are in PATH (for AWS CLI)
                  export PATH="/snap/bin:$PATH"

                  # Parameters (substituted by SSM at runtime)
                  VERSION="{{ Version }}"
                  S3_BUCKET="{{ S3Bucket }}"
                  PLUGIN_NAME="{{ PluginName }}"
                  DEPLOY_PATH="{{ DeployPath }}"
                  BACKUP_RETENTION="{{ BackupRetention }}"

                  echo "============================================"
                  echo "Traefik Plugin Deployment"
                  echo "============================================"
                  echo "Plugin:      $PLUGIN_NAME"
                  echo "Version:     $VERSION"
                  echo "S3 Bucket:   $S3_BUCKET"
                  echo "Deploy Path: $DEPLOY_PATH"
                  echo "Timestamp:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
                  echo "============================================"

                  # Check AWS CLI is available
                  if ! command -v aws &> /dev/null; then
                    echo "ERROR: AWS CLI not found. Run the bootstrap-instance document first."
                    exit 1
                  fi

                  # Capture Traefik state BEFORE deployment
                  echo ""
                  echo "Pre-deployment Traefik state:"
                  TRAEFIK_WAS_RUNNING=false
                  TRAEFIK_TYPE="none"

                  if systemctl is-active --quiet traefik 2>/dev/null; then
                    TRAEFIK_WAS_RUNNING=true
                    TRAEFIK_TYPE="systemd"
                    echo "  Traefik service: active (systemd)"
                  elif systemctl is-enabled --quiet traefik 2>/dev/null; then
                    TRAEFIK_TYPE="systemd"
                    echo "  Traefik service: enabled but not active (systemd)"
                  elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q traefik; then
                    TRAEFIK_WAS_RUNNING=true
                    TRAEFIK_TYPE="docker"
                    echo "  Traefik container: running (docker)"
                  else
                    echo "  Traefik: not running"
                  fi

                  # Create backup
                  BACKUP_PATH="$${DEPLOY_PATH}.backup.$(date +%Y%m%d%H%M%S)"
                  if [ -d "$DEPLOY_PATH" ]; then
                    echo ""
                    echo "Creating backup: $BACKUP_PATH"
                    sudo cp -r "$DEPLOY_PATH" "$BACKUP_PATH"
                  fi

                  # Download and extract
                  echo ""
                  echo "Downloading plugin from S3..."
                  TARBALL="/tmp/$${PLUGIN_NAME}-$${VERSION}.tar.gz"
                  aws s3 cp "s3://$${S3_BUCKET}/traefik-plugins/$${PLUGIN_NAME}-$${VERSION}.tar.gz" "$TARBALL"

                  echo "Extracting to $DEPLOY_PATH..."
                  sudo mkdir -p "$DEPLOY_PATH"
                  sudo tar -xzf "$TARBALL" -C "$DEPLOY_PATH"
                  rm -f "$TARBALL"

                  # Reload Traefik if it was running
                  echo ""
                  if [ "$TRAEFIK_WAS_RUNNING" = true ]; then
                    echo "Reloading Traefik..."
                    if [ "$TRAEFIK_TYPE" = "systemd" ]; then
                      sudo systemctl reload traefik || sudo systemctl restart traefik
                    elif [ "$TRAEFIK_TYPE" = "docker" ]; then
                      docker restart traefik
                    fi
                    echo "Waiting for Traefik to stabilize (15 seconds)..."
                    sleep 15
                  else
                    echo "Traefik was not running, skipping reload"
                  fi

                  # Health checks
                  echo ""
                  echo "Running health checks..."
                  PLUGIN_DEPLOYED=false
                  TRAEFIK_OK=false

                  # Critical check: Plugin .go files exist in deploy path
                  GO_FILE_COUNT=$(find "$DEPLOY_PATH" -maxdepth 1 -name '*.go' ! -name '*_test.go' ! -name '*.go.bak' 2>/dev/null | wc -l | tr -d ' ')
                  if [ "$GO_FILE_COUNT" -gt 0 ]; then
                    echo "Plugin deployed: $GO_FILE_COUNT .go file(s) in $DEPLOY_PATH"
                    PLUGIN_DEPLOYED=true
                  else
                    echo "No .go plugin files found in $DEPLOY_PATH"
                  fi

                  # Secondary check: Traefik state (only checked if it was running before)
                  if [ "$TRAEFIK_WAS_RUNNING" = true ]; then
                    TRAEFIK_PID=$(pgrep -x traefik 2>/dev/null || pgrep -f '/traefik' 2>/dev/null | head -1)
                    if [ -n "$TRAEFIK_PID" ] && [ -d "/proc/$TRAEFIK_PID" ]; then
                      echo "Traefik process running (PID: $TRAEFIK_PID)"
                      TRAEFIK_OK=true

                      # Check uptime - require at least 30 seconds to ensure stability
                      UPTIME=$(ps -o etimes= -p "$TRAEFIK_PID" 2>/dev/null | tr -d ' ')
                      if [ -n "$UPTIME" ] && [ "$UPTIME" -ge 30 ]; then
                        echo "Traefik stable (uptime: $${UPTIME}s)"
                      elif [ -n "$UPTIME" ] && [ "$UPTIME" -ge 5 ]; then
                        echo "WARNING: Traefik uptime acceptable but low: $${UPTIME}s (prefer 30s+)"
                      else
                        echo "WARNING: Traefik uptime very low: $${UPTIME:-unknown}s"
                      fi
                    else
                      echo "WARNING: Traefik was running but now is not responding"
                    fi
                  else
                    echo "Traefik was not running before deployment (pre-existing condition)"
                  fi

                  echo ""

                  # Determine success criteria:
                  # - Plugin MUST be deployed
                  # - If Traefik was running before, it should still be running after
                  SHOULD_ROLLBACK=false

                  if [ "$PLUGIN_DEPLOYED" != true ]; then
                    echo "============================================"
                    echo "FAILED: Plugin deployment failed"
                    echo "============================================"
                    SHOULD_ROLLBACK=true
                  elif [ "$TRAEFIK_WAS_RUNNING" = true ] && [ "$TRAEFIK_OK" != true ]; then
                    echo "============================================"
                    echo "WARNING: Plugin deployed but Traefik is unhealthy"
                    echo "   (was running before, not running after)"
                    echo "============================================"
                    SHOULD_ROLLBACK=true
                  else
                    echo "============================================"
                    echo "SUCCESS: Deployment successful: $VERSION"
                    if [ "$TRAEFIK_WAS_RUNNING" != true ]; then
                      echo "   Note: Traefik was not running (pre-existing issue)"
                    fi
                    echo "============================================"

                    # Cleanup old backups (keep last N based on BackupRetention)
                    echo ""
                    echo "Cleaning up old backups (keeping last $BACKUP_RETENTION)..."
                    ls -dt $${DEPLOY_PATH}.backup.* 2>/dev/null | tail -n +$((BACKUP_RETENTION + 1)) | xargs -r sudo rm -rf
                    echo "Done"
                  fi

                  # Rollback if needed
                  if [ "$SHOULD_ROLLBACK" = true ]; then
                    echo ""
                    echo "Initiating rollback..."

                    if [ -d "$BACKUP_PATH" ]; then
                      echo "Rolling back to: $BACKUP_PATH"
                      sudo rm -rf "$DEPLOY_PATH"
                      sudo mv "$BACKUP_PATH" "$DEPLOY_PATH"

                      if [ "$TRAEFIK_WAS_RUNNING" = true ]; then
                        if [ "$TRAEFIK_TYPE" = "systemd" ]; then
                          sudo systemctl restart traefik
                        elif [ "$TRAEFIK_TYPE" = "docker" ]; then
                          docker restart traefik
                        fi
                      fi

                      echo "Rollback complete"
                    else
                      echo "No backup available for rollback"
                    fi

                    exit 1
                  fi
  YAML

  tags = merge(local.module_tags, {
    Name    = local.deploy_doc_name
    Project = "traefik-plugins"
  })
}

resource "aws_ssm_document" "rollback" {
  name            = local.rollback_doc_name
  document_type   = "Command"
  document_format = "YAML"

  content = <<-YAML
    schemaVersion: '2.2'
    description: 'Rollback Traefik plugin to previous version'
    parameters:
      DeployPath:
        type: String
        default: "/home/ubuntu/traefik/plugins-local/src/github.com/traefik/qurl-router"
        description: "Path where the plugin is deployed"
    mainSteps:
      - action: aws:runShellScript
        name: rollbackPlugin
        inputs:
          runCommand:
            - |
              #!/bin/bash
                  # Rollback Traefik plugin to previous version
                  # SSM Parameters: DeployPath
                  set -e

                  DEPLOY_PATH="{{ DeployPath }}"

                  echo "============================================"
                  echo "Traefik Plugin Rollback"
                  echo "============================================"

                  # Find most recent backup
                  BACKUP=$(ls -dt $${DEPLOY_PATH}.backup.* 2>/dev/null | head -1)

                  if [ -z "$BACKUP" ] || [ ! -d "$BACKUP" ]; then
                    echo "ERROR: No backup found for rollback"
                    exit 1
                  fi

                  echo "Rolling back to: $BACKUP"

                  # Perform rollback
                  sudo rm -rf "$DEPLOY_PATH"
                  sudo mv "$BACKUP" "$DEPLOY_PATH"

                  # Restart Traefik
                  if systemctl is-active --quiet traefik; then
                    echo "Restarting Traefik (systemd)..."
                    sudo systemctl restart traefik
                  elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q traefik; then
                    echo "Restarting Traefik (docker)..."
                    docker restart traefik
                  fi

                  sleep 3

                  # Verify
                  TRAEFIK_PID=$(pgrep -x traefik 2>/dev/null || pgrep -f '/traefik' 2>/dev/null | head -1)
                  if [ -n "$TRAEFIK_PID" ]; then
                    echo ""
                    echo "============================================"
                    echo "SUCCESS: Rollback successful"
                    echo "============================================"
                  else
                    echo ""
                    echo "============================================"
                    echo "WARNING: Rollback complete but Traefik may not be running"
                    echo "============================================"
                    exit 1
                  fi
  YAML

  tags = merge(local.module_tags, {
    Name    = local.rollback_doc_name
    Project = "traefik-plugins"
  })
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "deploy" {
  name              = "/aws/ssm/traefik-plugins-${var.environment}"
  retention_in_days = 14

  tags = merge(local.module_tags, {
    Name = "traefik-plugins-${var.environment}-deploy-logs"
  })
}

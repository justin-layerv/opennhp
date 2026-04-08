# ============================================================================
# PACKER BUILD IAM ROLE (per-environment, dedicated)
#
# Used by .github/workflows/build-and-push.yml::packer-build to bake the
# Docker-optimized NHP Server AMI introduced in PR #252.
#
# Why a separate role from `nhp-${var.environment}-github-actions`:
#
#   The existing GitHub Actions role is broad: it covers terraform-apply,
#   ECS deploys, ECR pushes, plugin bucket writes, and several Terraform
#   sub-policies (EC2, IAM, services, data). Granting Packer's full
#   amazon-ebs builder permission set on top of that role would widen its
#   blast radius further — every workflow that already assumes it would
#   gain ec2:CreateKeypair / RunInstances / CreateImage / etc.
#
#   Packer needs a different shape of EC2 access than terraform-apply does
#   (the existing terraform-apply-ec2 policy scopes ec2:RunInstances to
#   launch-templates only, not arbitrary instances). Granting both shapes
#   to the same role mixes two threat models. The dedicated Packer role
#   keeps the bake-time vs deploy-time blast radii separate.
#
#   The trust policy for this role is also tighter: only the main branch
#   of the nhp repo (where packer-build's `if:` condition fires), no
#   pull_request, no traefik-plugins, no plugin repos.
#
# History:
#   PR #252 introduced packer-build but reused the existing
#   nhp-${var.environment}-github-actions role, which doesn't have any
#   amazon-ebs builder permissions. The first three post-#252 main runs
#   each surfaced a different latent bug:
#     1. Bad setup-packer SHA pin (fixed in #961)
#     2. Bad Packer version pin 1.14.4 (fixed in #965)
#     3. Missing Packer IAM permissions (fixed by THIS PR)
# ============================================================================

resource "aws_iam_role" "github_actions_packer" {
  name        = "nhp-${var.environment}-github-actions-packer"
  description = "GitHub Actions role for the packer-build job in ${var.github_org}/${var.github_repo} (${var.environment}). See terraform/modules/ecr/packer.tf for the rationale on why this is separate from the main github_actions role."

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
        # Tightest possible trust scope: only main branch of the nhp repo.
        # The packer-build job's own `if:` condition is
        #   github.ref == 'refs/heads/main' && github.event_name == 'push'
        # so the only OIDC subject that can assume this role is a push to
        # main. No pull_request, no traefik-plugins, no plugin repos.
        # Adding workflow_dispatch from main is fine because dispatched
        # runs from main also produce the refs/heads/main subject.
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
          ]
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-github-actions-packer"
    Component = "ecr"
    Purpose   = "packer-build"
  })
}

# Standard amazon-ebs builder permissions per the HashiCorp docs:
# https://developer.hashicorp.com/packer/integrations/hashicorp/amazon
#
# These are the minimum needed for the amazon-ebs source to:
#   - launch a temporary builder instance (RunInstances + KeyPair + SG)
#   - run provisioners over SSH (DescribeInstances + GetPasswordData)
#   - snapshot + register the AMI (CreateSnapshot + CreateImage + RegisterImage)
#   - clean up on success or failure (Terminate + Delete + Deregister)
#
# Plus a scoped ssm:PutParameter for the shell-local post-processor that
# publishes the resulting AMI ID to /{env}/nhp/server/ami-id (introduced
# in PR #252 and renamed in round 5 to align with the existing /{env}/nhp/server/*
# convention). The SSM grant is scoped to the exact parameter path so
# this role cannot write to any other SSM parameter, even within
# /{env}/nhp/server/* (e.g. it can't touch image-tag or asg-name).
resource "aws_iam_policy" "github_actions_packer_build" {
  name        = "nhp-${var.environment}-github-actions-packer-build"
  description = "Permissions for the packer-build job to bake the NHP Server Docker AMI (introduced in #252, granted in this PR)."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PackerAmazonEBSBuilder"
        Effect = "Allow"
        Action = [
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CopyImage",
          "ec2:CreateImage",
          "ec2:CreateKeypair",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteKeyPair",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSnapshot",
          "ec2:DeleteVolume",
          "ec2:DeregisterImage",
          "ec2:DescribeImageAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeSubnets",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DetachVolume",
          "ec2:GetPasswordData",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:RegisterImage",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
        ]
        Resource = "*"
        # Region-scope every EC2 action so this role can only operate
        # in the deployment region. Without this condition the role
        # could launch instances, create snapshots, and copy AMIs in
        # any AWS region (within the account) — Packer only ever runs
        # in the region the workflow's AWS_REGION env var sets, so
        # nothing legitimate is constrained by this. The condition
        # blocks the worst-case "compromised role spins up GPU
        # instances in ap-southeast-1" scenario.
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = local.region
          }
        }
      },
      {
        Sid      = "SSMPutAMIIDParameter"
        Effect   = "Allow"
        Action   = ["ssm:PutParameter"]
        Resource = "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/server/ami-id"
      },
      {
        # Packer's SSM put-parameter call also needs ssm:GetParameter to
        # read the parameter back for the --overwrite path. AWS CLI's
        # put-parameter --overwrite is technically a Put-only operation
        # but some IAM contexts require Get for the response handling.
        # Scoping to the same single parameter as the Put.
        Sid      = "SSMGetAMIIDParameter"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/server/ami-id"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "github_actions_packer_build" {
  role       = aws_iam_role.github_actions_packer.name
  policy_arn = aws_iam_policy.github_actions_packer_build.arn
}

output "github_actions_packer_role_arn" {
  description = "ARN of the dedicated IAM role assumed by the build-and-push.yml::packer-build job. After applying this module, store this ARN in the GitHub Actions repo secret AWS_PACKER_SANDBOX_ROLE_ARN (sandbox) or AWS_PACKER_PROD_ROLE_ARN (prod)."
  value       = aws_iam_role.github_actions_packer.arn
}

output "github_actions_packer_role_name" {
  description = "Name of the dedicated IAM role assumed by the packer-build job."
  value       = aws_iam_role.github_actions_packer.name
}

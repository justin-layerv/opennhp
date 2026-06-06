# IAM MFA enforcement (#1138 Steps 2 & 3)
#
# The purple-team review found human console logins without MFA. Asking users
# to turn MFA on is not enforcement — a phished password stays usable until the
# IAM policy itself refuses to act for a session that did not present MFA.
#
# IMPORTANT — attachment is deliberately NOT done here, because the human IAM
# identities that log into this account are NOT managed in this Terraform. The
# only aws_iam_user in the tree is auth0_ses (a service SMTP user), and CI uses
# GitHub OIDC, which carries no MFA claim and MUST stay exempt. This file
# therefore ships the *policy artifact* and exports its ARN (see outputs.tf); a
# human with IAM access must attach require_mfa to the user(s)/group(s) those
# console identities live in. Tracking that attachment is an out-of-repo
# follow-up, not something this PR can close on its own.
#
# We do NOT fold this condition into aws_iam_policy.permission_boundary: that
# boundary is attached to service roles (Lambda/EC2/ECS) which never present
# MFA, so a deny-without-MFA there would break the running fleet. The two are
# orthogonal — the boundary caps service-role permissions; require_mfa gates
# human sessions.
#
# The policy is the canonical AWS "self-service MFA + deny-everything-else"
# shape:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html

resource "aws_iam_policy" "require_mfa" {
  count       = var.enable_require_mfa_policy ? 1 : 0
  name        = "${var.name_prefix}-require-mfa"
  description = "Deny all actions for a session that did not present MFA, except the self-service actions needed to enroll an MFA device. Attach to human IAM users/groups (#1138)."

  # In the per-user Resource ARNs the account_id from data.aws_caller_identity
  # IS interpolated by Terraform (pins the policy to this account, marginally
  # tighter than the canonical tutorial's wildcard), while the aws:username IAM
  # policy variable is escaped as a doubled-dollar so Terraform leaves it intact
  # for AWS to resolve per-caller at request time.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Readable without MFA so a brand-new user can discover the password
        # policy and list the MFA devices they need to enroll.
        Sid    = "AllowViewAccountInfo"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListVirtualMFADevices",
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnPasswordAndUser"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetUser",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnVirtualMFADevice"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnUserMFA"
        Effect = "Allow"
        Action = [
          "iam:DeactivateMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}"
      },
      {
        # The fence. Everything except the self-service enrollment set above
        # is denied unless the session presented MFA. BoolIfExists (not Bool)
        # so a principal type that never carries the key is evaluated as
        # "false" (denied) rather than skipping the statement. Note
        # DeactivateMFADevice is intentionally NOT in NotAction — removing
        # your own MFA requires an MFA-authenticated session.
        Sid    = "DenyAllExceptListedUnlessMFAPresent"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "sts:GetSessionToken",
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
    ]
  })

  tags = merge(var.tags, { Component = "security" })
}

# Account-wide IAM password policy (#1138 Step 3)
#
# NOTE: an AWS account password policy CANNOT require MFA — that is what the
# require_mfa policy above is for. This hardens the password leg only (length,
# complexity, rotation, reuse) so a console password that does slip through is
# harder to guess or brute-force.
#
# It is an account SINGLETON: applying this OVERWRITES any password policy set
# manually or by another stack, and tightening it can force existing IAM users
# to reset their password at next sign-in. hard_expiry is left false so an
# expired password is resettable at login rather than locking the user out.
# The toggle DEFAULTS OFF precisely because of that account-global blast radius
# — enabling it is a deliberate, separately-reviewed apply once the existing
# policy has been captured (see the prod rollout ledger entry for #1138).
resource "aws_iam_account_password_policy" "main" {
  count = var.enable_account_password_policy ? 1 : 0

  # Parameterization is deliberate: length and max-age are the two knobs an
  # operator realistically tunes per environment, so they are variables with
  # validated bounds. Complexity (the four require_* booleans) and
  # reuse-prevention are fixed at CIS AWS Foundations values (complexity is the
  # CIS 1.8 charset set; password_reuse_prevention = 24 is CIS 1.9) — they are
  # the floor we don't want lowered, so they are hardcoded rather than exposed
  # as footguns.
  minimum_password_length        = var.password_minimum_length
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = var.password_max_age_days
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

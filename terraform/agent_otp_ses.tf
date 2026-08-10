# =====================================================================
# Agent-registration email OTP — SES v2 sender + pepper secret (T1)
# =====================================================================
#
# Everything in this file is gated on `var.agent_otp_enabled` (PATH B). An env
# with the OTP path dark (sandbox during burn-in, prod until launch) has
# `agent_otp_enabled = false` → every resource here has `count = 0` and NOTHING
# is created. This is the same dark-launch discipline the bootstrap chain and the
# qURL v2 blocks use (a flag flip, not a code change, activates the surface).
#
# WHY INLINE AT ROOT (not a modules/agent-otp-ses/ submodule):
#   - The Route53 zone this env manages is a ROOT concern
#     (`data.aws_route53_zone.main` / `var.hosted_zone_id` in main.tf) — the DKIM
#     + MAIL FROM records must land in that zone, so the records belong wherever
#     the zone id resolves.
#   - The single consumer is qurl-service, whose OTP env vars (email_from, pepper)
#     are already wired at the root. A submodule would force threading the zone
#     id, region, flag, and tags in and the identity/config-set ARNs back out for
#     a single-env, single-consumer surface.
#   - Precedent: `terraform/qurl_service_outcomes.tf` is a root-level cross-cutting
#     observability file for exactly this reason (it reads the qurl-service log
#     group + the shared SNS topic, both root concerns). This file mirrors that
#     placement for the SES sender it fronts.
#
# ZONE HANDLING: records are written to `local.agent_otp_zone_id`, which prefers
# the explicit `var.hosted_zone_id` (prod + sandbox both set it — the zone lives
# cross-account in layerv-mgmt, so the data-source lookup is bypassed) and falls
# back to `data.aws_route53_zone.main[0].zone_id`. A precondition below hard-fails
# the apply if the OTP path is on but no zone id resolves, so we never guess prod
# DNS. The DKIM + MAIL FROM records use `provider = aws.route53_mgmt` (the same
# cross-account assume-role provider EVERY other aws_route53_record in main.tf uses
# for the layerv.{ai,xyz} zones), which is correct for the cross-account
# prod/sandbox case and degrades to a same-account no-op when no role ARN is set —
# see the per-resource provider note below. The SES identity/config-set themselves
# live in the workload account (default provider), so only the DNS crosses accounts.

locals {
  agent_otp_ses_enabled = var.agent_otp_enabled
  # Keep the shared SES sender/configuration set for native UDP Authority OTP,
  # but remove the qurl-service-only pepper in the coordinated HTTP retirement.
  agent_otp_legacy_secret_enabled = local.agent_otp_ses_enabled && !var.retire_http_agent_lifecycle

  # Sender domain derived from the From address (noreply@<domain> → <domain>).
  # split() on "@" and take element 1. Empty-safe: when OTP is dark
  # agent_otp_email_from is "" and this local is unused (all count = 0).
  agent_otp_sender_domain = var.agent_otp_email_from != "" ? split("@", var.agent_otp_email_from)[1] : ""

  # Custom MAIL FROM subdomain under the sender domain. A dedicated bounce/
  # complaint return-path domain (SPF-aligned) is SES best practice and required
  # for DMARC alignment on the envelope sender. `mail.<domain>` is the convention.
  agent_otp_mail_from_domain = local.agent_otp_sender_domain != "" ? "mail.${local.agent_otp_sender_domain}" : ""

  # Zone the DKIM + MAIL FROM records land in. Prefer the explicit id (the
  # cross-account layerv-mgmt zone in prod/sandbox); fall back to the same-account
  # data source. May be null when neither is set — the precondition below fences
  # that so we never write records into an unresolved/guessed zone.
  agent_otp_zone_id = var.hosted_zone_id != null ? var.hosted_zone_id : try(data.aws_route53_zone.main[0].zone_id, null)

  agent_otp_tags = merge(local.common_tags, {
    Component = "agent-otp-ses"
    Service   = "qurl"
  })

  # SINGLE SOURCE OF TRUTH for the SES v2 configuration-set name. Used HERE by the
  # config set + its event destination default dimension + the identity wiring, AND
  # by the bounce alarm in qurl_service_outcomes.tf as the `ses:configuration-set`
  # metric dimension. A plain string (NOT aws_sesv2_configuration_set.agent_otp[0].
  # configuration_set_name) so it evaluates even when the resource is count=0, and
  # so the alarm's dimension can never drift from the real config-set name — a drift
  # would silently strand the launch-blocking bounce alarm in INSUFFICIENT_DATA.
  agent_otp_config_set_name = "${local.name_prefix}-agent-otp"
}

# ── Fail-closed fence: OTP on but no zone to write DNS into ──
# We refuse to half-create an SES identity whose DKIM/MAIL-FROM records can't be
# written — that would leave email un-authenticated (DMARC fail → spam-foldered
# or bounced) with no plan-time signal. Belt-and-suspenders to the qurl_service /
# compute preconditions in main.tf.
resource "terraform_data" "agent_otp_ses_preconditions" {
  count = local.agent_otp_ses_enabled ? 1 : 0

  lifecycle {
    precondition {
      # != null AND != "": var.hosted_zone_id is a string, so an empty "" is
      # non-null and would slip past a null-only check, then fail deep in apply
      # when the DKIM/MAIL-FROM records try to write to an empty zone id. Fence
      # both here so the failure surfaces at plan with this message.
      condition     = local.agent_otp_zone_id != null && local.agent_otp_zone_id != ""
      error_message = "agent_otp_enabled=true but no Route53 zone id resolved (var.hosted_zone_id is null or empty and no var.hosted_zone data source matched). The SES DKIM + MAIL FROM records have nowhere to land. Set hosted_zone_id (the zone that owns the agent_otp_email_from domain) before enabling the OTP path."
    }
    precondition {
      condition     = local.agent_otp_sender_domain != ""
      error_message = "agent_otp_enabled=true but the sender domain could not be derived from agent_otp_email_from. Set agent_otp_email_from to a bare local@domain address."
    }
  }
}

# =====================================================================
# QURL_AGENT_OTP_PEPPER secret
# =====================================================================
#
# The pepper qurl-service mixes into the OTP hash (server-side secret, 32+ chars).
# Mirrors the `nhp_internal_auth` pattern exactly (main.tf): the secret RESOURCE
# is created by Terraform, but the VALUE is seeded out-of-band via a local-exec
# (get-random-password) so it never lands in Terraform state, and a check block
# confirms the version is populated + meets the 32-char floor. The legacy-secret
# gate lets the shared SES sender survive the HTTP qurl-service retirement.
resource "aws_secretsmanager_secret" "agent_otp_pepper" {
  count = local.agent_otp_legacy_secret_enabled ? 1 : 0

  name                    = "${local.name_prefix}-agent-otp-pepper"
  description             = "OTP hash pepper for qurl-service agent-registration email OTP (QURL_AGENT_OTP_PEPPER) — server-side secret, 32+ chars"
  recovery_window_in_days = var.environment == "prod" ? 30 : 0
  kms_key_id              = module.kms.secrets_key_arn

  tags = merge(local.agent_otp_tags, {
    Name = "${local.name_prefix}-agent-otp-pepper"
  })
}

# 48 bytes > the 32-char floor qurl-service enforces. Value never appears in
# Terraform state — get-random-password + put-secret-value run entirely inside
# this local-exec, and the value is NOT read back into state anywhere (there is
# deliberately no `aws_secretsmanager_secret_version` data source for it — see the
# note at the bottom of this block). Same rationale as nhp_internal_auth_seed:
# --exclude-punctuation keeps the value safe through the ECS task-def env transport
# (qurl-service reads it raw). Recovery: if the local-exec fails mid-apply the
# secret exists but is unpopulated and qurl-service refuses to start OTP; re-run
# with `terraform apply -replace=terraform_data.agent_otp_pepper_seed`.
#
# ROLLOUT NOTE: the operator MAY instead populate this secret by hand (the ledger
# lists that as step c). The seed is idempotent-once: it writes only when the
# terraform_data is (re)created, so a hand-populated value set AFTER the first
# apply is not clobbered on subsequent applies. To force a rotation, taint/replace
# the seed. If you prefer a fully hand-managed value, comment out this seed
# resource — the 48-byte length is then whatever you write, and qurl-service's
# startup validation still enforces the 32-char floor fail-closed.
#
# NO TERRAFORM-LEVEL LENGTH ASSERTION: earlier this block carried a `check` that
# read the version back to assert the 32-char floor, but a `check`'s nested data
# source can't be count-gated (and the pepper is count-gated), so it had to be
# hoisted to a top-level `data.aws_secretsmanager_secret_version` — which persists
# `secret_string` into the (KMS-encrypted S3) state on every plan/apply,
# contradicting the "never in state" guarantee above. The length is already
# guaranteed twice without re-reading the secret: (1) the 48-char get-random-password
# seed here, and (2) qurl-service's boot Config.Validate, which rejects a
# <32-char QURL_AGENT_OTP_PEPPER fail-closed at startup. A redundant terraform-level
# re-read isn't worth putting the secret in state, so it is intentionally omitted.
resource "terraform_data" "agent_otp_pepper_seed" {
  count = local.agent_otp_legacy_secret_enabled ? 1 : 0

  triggers_replace = [aws_secretsmanager_secret.agent_otp_pepper[0].arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      SECRET_VALUE=$(aws secretsmanager get-random-password \
        --region "${data.aws_region.current.id}" \
        --password-length 48 \
        --exclude-punctuation \
        --query RandomPassword --output text)
      if [ -z "$SECRET_VALUE" ]; then
        echo "ERROR: get-random-password returned empty" >&2
        exit 1
      fi
      aws secretsmanager put-secret-value \
        --region "${data.aws_region.current.id}" \
        --secret-id "${aws_secretsmanager_secret.agent_otp_pepper[0].id}" \
        --secret-string "$SECRET_VALUE" > /dev/null
    EOT
  }
}

# =====================================================================
# SES v2 email identity (sender domain) + EasyDKIM
# =====================================================================
#
# Domain identity for the sender domain (derived from agent_otp_email_from). SES
# EasyDKIM: dkim_signing_attributes.next_signing_key_length picks the key length;
# SES returns three CNAME tokens (dkim_signing_attributes.tokens) we publish
# below. Once those CNAMEs resolve + verify, SES DKIM-signs every message from
# this domain.
#
# PRODUCTION ACCESS: a brand-new SES identity starts in the SANDBOX (can only send
# to verified recipients, low quota). Requesting production access is a console/
# support action, NOT a Terraform resource — it's the first step in the rollout
# ledger. This file provisions the identity + DNS + config set; the sandbox→prod
# move is operator-owned.
resource "aws_sesv2_email_identity" "agent_otp_sender" {
  count = local.agent_otp_ses_enabled ? 1 : 0

  depends_on = [time_sleep.agent_otp_ses_iam_propagation]

  email_identity         = local.agent_otp_sender_domain
  configuration_set_name = aws_sesv2_configuration_set.agent_otp[0].configuration_set_name

  dkim_signing_attributes {
    # EasyDKIM (AWS-managed keys). RSA_2048_BIT is the stronger of the two SES
    # offers; the tokens SES returns are published as CNAMEs below.
    next_signing_key_length = "RSA_2048_BIT"
  }

  tags = merge(local.agent_otp_tags, {
    Name = "${local.name_prefix}-agent-otp-sender"
  })
}

# Custom MAIL FROM domain (envelope-sender / return-path). Aligns SPF with the
# From domain for DMARC and gives bounces/complaints a domain we control.
# behavior_on_mx_failure = REJECT: if the MAIL FROM MX record ever disappears,
# REJECT the send rather than silently falling back to SES's amazonses.com
# envelope (which breaks SPF alignment and can degrade deliverability invisibly).
resource "aws_sesv2_email_identity_mail_from_attributes" "agent_otp_sender" {
  count = local.agent_otp_ses_enabled ? 1 : 0

  email_identity         = aws_sesv2_email_identity.agent_otp_sender[0].email_identity
  mail_from_domain       = local.agent_otp_mail_from_domain
  behavior_on_mx_failure = "REJECT_MESSAGE"
}

# =====================================================================
# Route53 records — DKIM CNAMEs + MAIL FROM MX/TXT
# =====================================================================

# PROVIDER — aws.route53_mgmt on ALL three records, matching EVERY other
# aws_route53_record in this tree that writes the layerv.{ai,xyz} zones (grep
# `provider = aws.route53_mgmt` in main.tf — connect, bootstrap_alb, qurl_api,
# qurl_link, developer_portal, etc.). The zone lives cross-account in layerv-mgmt
# (hosted_zone_id = Z0748438C8EK6UAW94ST prod / Z10394893FM38A1RXLL32 sandbox), so
# the DEFAULT provider cannot write it. The route53_mgmt provider assumes
# nhp-ac-route53-access in layerv-mgmt when var.cross_account_route53_role_arn is
# set, and degrades to a same-account no-op assume-role block when it isn't — so
# this is correct for both the cross-account (prod/sandbox) and any same-account
# env. Using the default provider here would fail the apply with AccessDenied on
# the cross-account zone.

# Three EasyDKIM CNAMEs (<token>._domainkey.<domain> → <token>.dkim.amazonses.com).
#
# `count = 3`, NOT `for_each` over the token set: EasyDKIM ALWAYS returns exactly 3
# tokens, and on the first apply that flips agent_otp_enabled=true the identity does
# not exist yet, so `dkim_signing_attributes[0].tokens` is unknown at plan time.
# Terraform can derive `count` (a known 3) from that apply, but CANNOT derive
# `for_each` KEYS from an unknown set — it aborts the entire plan with
# "Invalid for_each argument: … cannot be determined until apply" before creating
# anything (exactly the ledger's first apply). With count, only the token VALUES
# are unknown (indexed per count.index), which Terraform tolerates. Trade-off: if
# SES ever rotated a single token, count-indexing could re-associate more records
# than for_each would — acceptable here because EasyDKIM tokens are stable for the
# identity's life and a full rotation replaces all three together.
resource "aws_route53_record" "agent_otp_dkim" {
  count    = local.agent_otp_ses_enabled ? 3 : 0
  provider = aws.route53_mgmt

  zone_id = local.agent_otp_zone_id
  name    = "${aws_sesv2_email_identity.agent_otp_sender[0].dkim_signing_attributes[0].tokens[count.index]}._domainkey.${local.agent_otp_sender_domain}"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_sesv2_email_identity.agent_otp_sender[0].dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}

# MAIL FROM MX — points the custom envelope domain at the regional SES inbound
# feedback MX. Region-specific: feedback-smtp.<region>.amazonses.com.
resource "aws_route53_record" "agent_otp_mail_from_mx" {
  count    = local.agent_otp_ses_enabled ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = local.agent_otp_zone_id
  name    = local.agent_otp_mail_from_domain
  type    = "MX"
  ttl     = 600
  records = ["10 feedback-smtp.${data.aws_region.current.id}.amazonses.com"]
}

# MAIL FROM SPF (TXT) — authorizes amazonses.com to send for the envelope domain.
resource "aws_route53_record" "agent_otp_mail_from_txt" {
  count    = local.agent_otp_ses_enabled ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = local.agent_otp_zone_id
  name    = local.agent_otp_mail_from_domain
  type    = "TXT"
  ttl     = 600
  records = ["v=spf1 include:amazonses.com ~all"]
}

# =====================================================================
# SES v2 configuration set (reputation + engagement metrics)
# =====================================================================
#
# The config set the sender identity uses (wired via configuration_set_name on
# the identity above). Enables reputation tracking + sending, and fans bounce/
# complaint/delivery/reject/send events to CloudWatch so deliverability is
# observable. The event-destination emits CloudWatch metrics dimensioned by
# ses:configuration-set, which future alarms can key on (the send_failed slog
# alarm in qurl_service_outcomes.tf is the launch-blocking one; these SES-native
# events are the corroborating deliverability signal).
resource "aws_sesv2_configuration_set" "agent_otp" {
  count = local.agent_otp_ses_enabled ? 1 : 0

  depends_on = [time_sleep.agent_otp_ses_iam_propagation]

  configuration_set_name = local.agent_otp_config_set_name

  delivery_options {
    tls_policy = "REQUIRE"
  }

  reputation_options {
    reputation_metrics_enabled = true
  }

  sending_options {
    sending_enabled = true
  }

  tags = merge(local.agent_otp_tags, {
    Name = local.agent_otp_config_set_name
  })
}

# CloudWatch event destination — bounce/complaint/delivery/reject/rendering
# failures land as SES CloudWatch metrics (namespace AWS/SES) dimensioned by the
# configuration set. A hard bounce or complaint spike here is the SES-native
# corroboration of the send_failed slog alarm.
resource "aws_sesv2_configuration_set_event_destination" "agent_otp_cloudwatch" {
  count = local.agent_otp_ses_enabled ? 1 : 0

  configuration_set_name = aws_sesv2_configuration_set.agent_otp[0].configuration_set_name
  event_destination_name = "${local.name_prefix}-agent-otp-cw"

  event_destination {
    enabled              = true
    matching_event_types = ["BOUNCE", "COMPLAINT", "DELIVERY", "REJECT", "RENDERING_FAILURE"]

    cloud_watch_destination {
      dimension_configuration {
        dimension_name          = "ses:configuration-set"
        dimension_value_source  = "MESSAGE_TAG"
        default_dimension_value = local.agent_otp_config_set_name
      }
    }
  }
}

# =====================================================================
# Per-PR live-email gate — GitHub Actions ses:SendEmail grant (NON-PROD)
# =====================================================================
#
# qurl-service runs a `livemail`-tagged Go test on every PR targeting main
# (.github/workflows/email-live-send.yml). It sends a REAL message through REAL
# SES, as the real sender identity, stamped with the real configuration set,
# to the AWS mailbox simulator success address. That is the only way to prove
# in a PR's own CI that the identity is verified, the config set exists, the
# rendered MIME is something SES accepts, and the caller is actually authorized
# — none of which a fake SES client can establish.
#
# WHY A NEW ROLE IS NEEDED AT ALL: the existing ses:SendEmail grants belong to
# the qurl-service ECS task role (modules/qurl-service: task_agent_otp_ses) and
# the Connector Authority ca-iro-cell* Lambda exec roles (Sid OTPSendEmail).
# Neither is assumable from GitHub Actions, so without this the gate fails
# closed with AccessDenied.
#
# SCOPE: the sender DOMAIN identity AND the configuration set (SESv2 SendEmail
# with a configuration_set_name authorizes ses:SendEmail against BOTH; an
# identity-only grant AccessDenies on the config-set), constrained by
# ses:FromAddress to the configured sender and by ses:Recipients to the mailbox
# simulator. Not Resource="*".
#
# NON-PROD ONLY, BY CONSTRAINT: the fence below fails the plan if this flag is
# ever set in prod. CI must not be able to originate mail from the prod sender
# identity (noreply@notify.layerv.ai) — a compromised or merely careless
# workflow would be sending as the address customers receive real OTPs from.
# The gate targets sandbox and that is the only place the grant may exist.
locals {
  agent_otp_ci_send_gate_permitted = var.agent_otp_ci_send_gate_enabled && local.agent_otp_ses_enabled

  # The ONLY address the gate role may mail. AWS's mailbox simulator: SES
  # delivers it, no real inbox receives it, and it does not touch sending
  # reputation. Pinning it in IAM is what keeps the role harmless in the hands
  # of an arbitrary PR branch.
  agent_otp_ci_send_gate_recipient = "success@simulator.amazonses.com"
}

resource "terraform_data" "agent_otp_ci_send_gate_fence" {
  count = var.agent_otp_ci_send_gate_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.environment != "prod"
      error_message = "agent_otp_ci_send_gate_enabled must never be true in prod: it would let GitHub Actions send mail as the production OTP sender identity. The per-PR live-email gate targets sandbox only."
    }
    precondition {
      condition     = local.agent_otp_ses_enabled
      error_message = "agent_otp_ci_send_gate_enabled=true requires agent_otp_enabled=true — the grant scopes to the SES identity and configuration set that gate creates, and would reference resources that do not exist."
    }
    precondition {
      # An empty repo name would produce the trust subject
      # "repo:<org>/:pull_request", which matches nothing — the role would be
      # created and every gate run would fail to assume it.
      condition     = trimspace(var.qurl_github_repo) != "" && trimspace(var.github_org) != ""
      error_message = "agent_otp_ci_send_gate_enabled=true requires non-empty github_org and qurl_github_repo: they form the OIDC trust subject the gate role is assumed under."
    }
  }
}

# A DEDICATED role, not a policy bolted onto nhp-<env>-github-actions.
#
# That role carries terraform-apply-equivalent permissions on the environment
# (see the SECURITY #1121 block on aws_iam_role.github_actions: full Terraform
# state + apply across compute/IAM/services/data, ECR push to every repo, ECS
# and S3 deploys, broad ssm:PutParameter). A `pull_request` workflow runs the
# workflow file FROM THE PR BRANCH, so granting PR-time access to that role
# would let any PR author rewrite the workflow and assume it. Handing an
# untrusted branch the keys to the environment is not an acceptable price for
# sending one email.
#
# So the gate gets its own role whose entire capability is "send exactly this
# email". Even with arbitrary workflow contents, a PR can do nothing with it
# beyond what the gate already does.
resource "aws_iam_role" "qurl_otp_email_gate" {
  count = local.agent_otp_ci_send_gate_permitted ? 1 : 0

  name = "${local.name_prefix}-qurl-otp-email-gate"
  # ASCII ONLY. IAM validates role descriptions against a charset that
  # excludes the em dash (U+2014) this line used to carry. Terraform plans
  # such a description cleanly and CreateRole then fails at apply with a
  # ValidationError, so the break lands on main rather than in review.
  # Keep punctuation in this string to plain ASCII.
  description = "Per-PR live OTP email gate for ${var.github_org}/${var.qurl_github_repo} - ses:SendEmail to the mailbox simulator only"

  # No environment: binding, deliberately. The `sandbox` GitHub environment's
  # deployment-branch policy rejects PR merge refs (that rejection is what
  # surfaced this design), and loosening it would re-open the privilege path
  # above. Trust the pull_request subject directly instead: it is exactly the
  # context the gate runs in, and nothing else.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = module.ecr.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.qurl_github_repo}:pull_request"
        }
      }
    }]
  })

  depends_on = [terraform_data.agent_otp_ci_send_gate_fence]

  tags = merge(local.agent_otp_tags, {
    Name = "${local.name_prefix}-qurl-otp-email-gate"
  })
}

resource "aws_iam_role_policy" "qurl_otp_email_gate" {
  count = local.agent_otp_ci_send_gate_permitted ? 1 : 0

  name = "agent-otp-ses-send-pr-gate"
  role = aws_iam_role.qurl_otp_email_gate[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AgentOTPPRGateSendEmail"
      Effect = "Allow"
      Action = ["ses:SendEmail"]
      Resource = [
        "arn:aws:ses:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:identity/${local.agent_otp_sender_domain}",
        "arn:aws:ses:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:configuration-set/${local.agent_otp_config_set_name}",
      ]
      Condition = {
        # Single-valued: exactly one envelope From per message, so a plain
        # operator is correct here.
        StringEquals = {
          "ses:FromAddress" = var.agent_otp_email_from
        }

        # MULTIVALUED. ses:Recipients resolves to every To/Cc/Bcc address on
        # the request, so it must be evaluated with a set operator — AWS
        # documents plain single-valued operators against a multivalued key as
        # unreliable. This is the control that makes an untrusted PR branch
        # holding this role uninteresting: IAM cannot scope trust to a
        # workflow_ref, so ANY qurl-service PR can rewrite the gate workflow
        # and assume this role. FromAddress alone would still let it send as
        # the reputable, DKIM-signed OTP sender, so the recipient pin is the
        # only thing standing between that and phishing from a trusted domain.
        "ForAllValues:StringEquals" = {
          "ses:Recipients" = [local.agent_otp_ci_send_gate_recipient]
        }

        # ForAllValues is VACUOUSLY TRUE when the key is absent from the
        # request, which would let a call carrying no recipients context slip
        # the pin entirely. Require the key to be present. (Same trap as the
        # dynamodb:LeadingKeys guards on the authority runtime policies.)
        Null = {
          "ses:Recipients" = "false"
        }
      }
    }]
  })
}

output "qurl_otp_email_gate_role_arn" {
  description = "Role the qurl-service per-PR live email gate assumes. Minimal by construction: ses:SendEmail as the OTP sender to the mailbox simulator, nothing else."
  value       = local.agent_otp_ci_send_gate_permitted ? aws_iam_role.qurl_otp_email_gate[0].arn : ""
}

# QURL FRP Server Module
#
# Deploys the FRP tunnel server (qurl-reverse-tunnel-server) as an EC2 Auto Scaling Group.
# The FRP server accepts connections from qurl-reverse-tunnel-client instances and proxies
# HTTP traffic to customer backends via vhost-based routing.
#
# Traffic flows:
# - AC Traefik -> frps:7000 (FRP control channel, WebSocket)
# - AC Traefik -> frps:8080 (vhost HTTP, proxied to customer backends)
#
# Multi-AZ tunnel routing (#1499): nhp-frps holds tunnel registrations in
# memory per process, so we can't put N instances behind one Cloud Map
# service and expect tunnel routing to work — DNS would return IPs in
# random order and ~(N-1)/N of requests would hit instances without the
# registration. Instead, we publish ONE Cloud Map service per AZ
# (`frps-a.${namespace}`, `frps-b.${namespace}`, ...) and qurl-service
# hashes `OwnerID` to a fixed AZ when emitting `frps_addr` in
# CreateResource / GetResourceTarget responses. Both `frpc` (registering
# tunnels) and the AC's qurl-router (forwarding vhost traffic) read the
# same `frps_addr` and converge on the same instance.
#
# Cross-repo contract enforced by:
# - frps_az_suffixes default `["a", "b", "c"]` (this module)
# - QURL_FRPS_AZ_SUFFIXES on qurl-service (must agree)
# - QURL_FRPS_DOMAIN     = "${namespace_name}"
# - QURL_FRPS_PORT       = ${frps_vhost_http_port}  (default 8080)
# Backend URL pattern: http://frps-${az_suffix}.${namespace_name}:${port}
#
# Cloud Map lifecycle during instance replacement (two distinct mechanisms):
#
# - The launch template's `lifecycle { create_before_destroy = true }`
#   (below) covers LT-version churn: a Terraform-driven LT change
#   provisions the new LT version before destroying the old one, so the
#   ASG never references a deleted version mid-apply.
# - The ASG's instance-refresh policy covers per-instance replacement
#   on a running fleet: each instance is launched, drained, and
#   terminated in series.
#
# Both paths produce a brief window (up to the 30s DNS TTL) where the
# new and old instances are registered against the same per-AZ Cloud
# Map service. Each per-AZ service has only ONE registration at steady
# state, so a replacement creates a transient pair. With WEIGHTED
# routing on a DNS-namespace service, the Route 53 resolver returns
# ONE A record per query (weight-biased; `1` default weight ⇒ uniform
# random) — `frpc` and `qurl-router` both consume `frps_addr` via DNS
# rather than the `DiscoverInstances` API, so each reconnect lands on
# one or the other instance until the old instance's systemd shutdown
# runs `ExecStop=cloudmap-deregister` (`BindsTo=qurl-reverse-tunnel-server.service`
# guarantees this fires when the ASG terminate sends SIGTERM). FRP
# clients reconnect on failure, so the ~30s split-brain isn't user-
# visible. A stricter approach — `aws_autoscaling_lifecycle_hook` on
# `Terminating:Wait` blocking until deregister completes — is tracked
# in #1089 alongside the custom health-check work.

terraform {
  required_version = ">= 1.5"
}

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  # True when an SNS alert destination is actually wired. trimspace guards
  # against a whitespace-only ARN; try() handles the null default.
  sns_destination_present = try(trimspace(var.alarm_sns_topic_arn) != "", false)
}

resource "terraform_data" "sns_alerts_contract" {
  lifecycle {
    precondition {
      condition     = !var.enable_sns_alerts || local.sns_destination_present
      error_message = "enable_sns_alerts=true requires a non-empty alarm_sns_topic_arn. Keep SNS-routed alarm resource counts gated on enable_sns_alerts, but wire the SNS ARN before enabling the gate."
    }
  }
}

check "sns_alerts_gate_matches_destination" {
  assert {
    condition     = var.enable_sns_alerts || !local.sns_destination_present
    error_message = "alarm_sns_topic_arn is set but enable_sns_alerts=false, so qurl-reverse-tunnel-server SNS alarms will not be created. Set enable_sns_alerts=true or clear alarm_sns_topic_arn."
  }
}

# Ubuntu 24.04 LTS (Noble Numbat) - consistent with AC module.
# The public SSM parameters from Canonical carry the `SecureString` attribute
# which the provider exposes as `sensitive`, producing `(sensitive value)` in
# plan output. Use `insecure_value` to surface the AMI ID in plans — AMI IDs
# are public catalog identifiers, not secrets.
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# Resolve the AZ of each private subnet so we can fence
# `frps_az_suffixes` against the actual AZ coverage of the VPC. Without
# this fence, an environment with subnets in only `[a, b]` paired with
# `frps_az_suffixes = ["a","b","c"]` would silently apply, create a
# `frps-c` Cloud Map service, and never register a single instance
# against it — every OwnerID hashing to `c` would resolve NXDOMAIN.
data "aws_subnet" "private" {
  for_each = toset(var.private_subnet_ids)
  id       = each.value
}

# Subnet/AZ alignment fence (#1499). Plan-time, so a misconfigured VPC
# fails on PR review rather than at runtime when the empty Cloud Map
# service starts returning NXDOMAIN.
resource "terraform_data" "subnet_az_alignment" {
  lifecycle {
    precondition {
      # Trailing letter of each subnet's AZ name. AWS AZ names are
      # `{region}{letter}`; we extract the same single-letter suffix
      # the user_data extracts at boot from IMDS so the two views
      # agree by construction.
      condition = length(setsubtract(
        toset(var.frps_az_suffixes),
        toset([for s in data.aws_subnet.private : substr(s.availability_zone, length(s.availability_zone) - 1, 1)])
      )) == 0
      error_message = "private_subnet_ids must include at least one subnet in every AZ listed in frps_az_suffixes — otherwise the corresponding Cloud Map service will never get a registration and OwnerIDs hashing to that suffix will resolve NXDOMAIN."
    }
  }
}

# ==================== Locals ====================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  # Register/Deregister IAM evaluates the Cloud Map service resource tags.
  # Use the same local for service tags, IAM conditions, and the plan-time
  # fence so a future tag-shape refactor cannot drift one side only.
  frps_cloudmap_required_tags = {
    Environment = var.environment
    Service     = "qurl-reverse-tunnel-server"
  }
  frps_cloudmap_required_tag_conditions = {
    for k, v in local.frps_cloudmap_required_tags : "aws:ResourceTag/${k}" => v
  }
  # Required tags are last so caller-supplied tags cannot override the
  # IAM boundary that lets FRPS register only to qurl reverse-tunnel services.
  frps_cloudmap_service_tags = merge(var.tags, local.frps_cloudmap_required_tags)

  # Name of the EC2_INSTANCE_LAUNCHING readiness hook (qurl-reverse-tunnel-server#195).
  # Single-sourced so the blue + green `aws_autoscaling_lifecycle_hook` resources and
  # the `frps_launch_lifecycle_hook_name` user_data template var cannot drift — a
  # mismatch would make `complete-lifecycle-action` target a non-existent hook and
  # every instance would wait out `heartbeat_timeout`. Same string on both ASGs is
  # fine: hook names are scoped per Auto Scaling group.
  frps_launch_lifecycle_hook_name = "${var.name_prefix}-frps-launch-readiness"

  # ==================== Effective ASG Sizing ====================
  # Resolve the legacy explicit triple (`min_size`/`max_size`/
  # `desired_capacity`) against the new per-AZ form (`min_size_per_az`/
  # `max_size_per_az`/`desired_capacity_per_az`). When the per-AZ var is
  # non-null, it wins and the effective fleet size is computed as
  # `per_az * length(frps_az_suffixes)`. When null, the legacy explicit
  # value is used unchanged.
  #
  # Backward compat note: callers that have `min_size = 3`, `max_size = 3`,
  # `desired_capacity = 3` set in tfvars (current sandbox/prod behavior)
  # produce effective `min/max/desired = 3` because the per-AZ vars default
  # to null. Switching to the per-AZ form is opt-in by setting
  # `desired_capacity_per_az = 1` (and friends) — same effective sizing,
  # but the source of truth is now "1 instance per AZ" instead of an
  # arithmetic product hand-baked into tfvars.
  az_count           = length(var.frps_az_suffixes)
  effective_min_size = var.min_size_per_az != null ? var.min_size_per_az * local.az_count : var.min_size
  effective_max_size = var.max_size_per_az != null ? var.max_size_per_az * local.az_count : var.max_size
  effective_desired_capacity = (
    var.desired_capacity_per_az != null
    ? var.desired_capacity_per_az * local.az_count
    : var.desired_capacity
  )

  # Shared ASG enabled_metrics list. Both blue and green ASGs publish the
  # same metric set (canary orchestrator's NLB-disabled health path reads
  # GroupInServiceInstances + GroupTotalInstances). Keep this in one
  # place so a future addition lands on both sides at once.
  #
  # Matches AC (`modules/ac/main.tf:1148`) and server
  # (`modules/compute/main.tf:1049`) — same 7 entries.
  #
  # `GroupUnHealthyInstanceCount` is deliberately omitted: AWS
  # rejects it from `EnableMetricsCollection` with ValidationError
  # 400 (not a valid metric type). The historical `*_asg_unhealthy`
  # alarms keep their names for dashboards/SNS routing, but #2041
  # rewires them to metric math over accepted ASG metrics
  # (`GroupDesiredCapacity - GroupInServiceInstances`). Don't
  # re-add this name here, and don't remove either metric from this
  # list without rewiring the capacity-deficit alarms too.
  asg_enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    region      = local.region
    account_id  = local.account_id
    environment = var.environment
    # Instances resolve the stable Cloud Map service name to the current
    # service ID at boot. Do not bake service IDs into user_data: the FRPS
    # ASG uses create_before_destroy, and making the launch template depend
    # on aws_service_discovery_service would propagate that lifecycle bit
    # into the Cloud Map services. Static service names plus CBD cannot
    # replace routing_policy (AWS marks it ForceNew).
    namespace_id         = var.namespace_id
    frps_az_suffixes     = var.frps_az_suffixes
    namespace_name       = var.namespace_name
    log_group_name       = aws_cloudwatch_log_group.frps.name
    frps_bind_port       = var.frps_bind_port
    frps_vhost_http_port = var.frps_vhost_http_port
    frps_dashboard_port  = var.frps_dashboard_port
    # EC2_INSTANCE_LAUNCHING hook name user_data passes to complete-lifecycle-action
    # (qurl-reverse-tunnel-server#195). Single-sourced with the hook resources.
    frps_launch_lifecycle_hook_name = local.frps_launch_lifecycle_hook_name
    frps_subdomain_host             = var.frps_subdomain_host
    qurl_api_internal_url           = var.qurl_api_internal_url
    qurl_api_token_secret_arn       = var.qurl_api_token_secret_arn
    nhp_server_internal_url         = var.nhp_server_internal_url
    nhp_internal_auth_secret_arn    = var.nhp_internal_auth_secret_arn
    connect_layerv_host             = var.connect_layerv_host
    qurl_tunnel_auth_mode           = var.qurl_tunnel_auth_mode
    tunnel_server_az_control_ports  = var.tunnel_server_az_control_ports
    ssm_image_tag_param             = local.ssm_image_tag_param_name
    ssm_min_client_version_param    = local.ssm_min_client_version_param_name
    min_client_version_file         = local.min_client_version_file_path
    min_client_version_disabled     = local.min_client_version_disabled_value
    # The user_data fallback command and the IAM grant must point at the
    # same bucket. Threading both from root (plugin_bucket_name + _arn)
    # instead of hardcoding the legacy `layerv-nhp-${env}-plugins` name
    # removes drift risk between the `aws s3 cp` call and its IAM grant.
    plugin_bucket_name = var.plugin_bucket_name
  })

  # Launch template user_data. FRPS now follows the AC/compute pattern: the
  # full rendered init script is uploaded to the plugin bucket and user_data is
  # only a small fetcher. The inline branch remains only as a structural
  # fallback for isolated module validation; with the current rendered script
  # size it is not a viable runtime rollback. Current sandbox/prod roots always
  # wire the bucket and download policy together.
  frps_launch_template_user_data = var.plugin_bucket_name != "" ? base64encode(<<-BOOTSTRAP
#!/bin/bash
set -exo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1

# Init script hash — md5 of local.user_data, NOT the S3 object's etag.
# The hash bumps the launch-template version whenever rendered init content changes.
# Referencing the S3 object's etag here can trigger the AWS provider's
# sensitive-attribute apply-time consistency bug on user_data updates. The md5
# is client-computable at plan time and mirrors the AC/compute bootstrap pattern.
# Init script hash: ${md5(local.user_data)}

retry_with_backoff() {
  local max_attempts=$1 delay=$2 max_delay=$3; shift 3
  local attempt=1
  while true; do
    if "$@"; then return 0; fi
    if [ "$attempt" -ge "$max_attempts" ]; then echo "ERROR: $* failed after $max_attempts attempts"; return 1; fi
    echo "$* failed (attempt $attempt/$max_attempts), retrying in $${delay}s..."
    sleep "$delay"; attempt=$((attempt + 1)); delay=$((delay * 2))
    if [ "$delay" -gt "$max_delay" ]; then delay=$max_delay; fi
  done
}
apt_get_with_retry() { retry_with_backoff 10 2 60 apt-get "$@"; }

if ! command -v curl &>/dev/null || ! command -v unzip &>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt_get_with_retry update -y
  apt_get_with_retry install -y curl unzip
fi

fetch_imds_token_and_region() {
  local token region
  for _ in 1 2 3 4 5; do
    token=""; region=""
    token=$(curl -fs -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60") || { sleep 2; continue; }
    [ -n "$token" ] || { sleep 2; continue; }
    region=$(curl -fs -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/region) || { sleep 2; continue; }
    [ -n "$region" ] || { sleep 2; continue; }
    TOKEN=$token; REGION=$region; return 0
  done
  return 1
}

if ! fetch_imds_token_and_region; then
  echo "FATAL: IMDSv2 unreachable after 5 attempts; refusing to boot FRPS blind"
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=frps,Environment=${var.environment},FailureMode=imds-unreachable" \
    --region "${local.region}" 2>/dev/null || true
  exit 1
fi

report_failure() {
  echo "BOOTSTRAP FAILED: $1"
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=frps,Environment=${var.environment}" \
    --region "$REGION" 2>/dev/null || true
}
trap 'report_failure "unexpected error on line $LINENO"' ERR

if ! command -v aws &>/dev/null; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -qo /tmp/awscliv2.zip -d /tmp && /tmp/aws/install --update
  rm -rf /tmp/awscliv2.zip /tmp/aws
fi

retry_with_backoff 3 5 30 aws s3 cp "s3://${var.plugin_bucket_name}/scripts/frps-init.sh" /tmp/frps-init.sh --region "$REGION"
chmod +x /tmp/frps-init.sh
exec /tmp/frps-init.sh
BOOTSTRAP
  ) : base64gzip(local.user_data)
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "frps" {
  name              = "/layerv/nhp/${var.environment}/frps"
  retention_in_days = var.environment == "prod" ? 90 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-logs"
    Component = "frps"
  })
}

# ==================== IAM Role ====================

resource "aws_iam_role" "frps" {
  name = "${var.name_prefix}-frps"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_instance_profile" "frps" {
  name = "${var.name_prefix}-frps"
  role = aws_iam_role.frps.name

  tags = var.tags
}

# SSM managed instance policy (for SSM Session Manager access)
resource "aws_iam_role_policy_attachment" "frps_ssm" {
  role       = aws_iam_role.frps.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "frps" {
  name = "frps-permissions"
  role = aws_iam_role.frps.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.frps.arn}:*"
      },
      # CloudWatch Metrics (for CloudWatch Agent)
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/NHP"
          }
        }
      },
      # SSM Parameters (read FRP config). user_data reads exact parameter
      # names: image-tag once at boot, and min-client-version at boot plus
      # via a timer. `GetParameters` (batch) and `GetParametersByPath`
      # (prefix scan) are intentionally omitted — least-privilege, and
      # widening is a one-line change if a future need arises.
      #
      # Both the canonical /<env>/nhp/reverse-tunnel-server/* path and the
      # legacy /<env>/nhp/frps/* path are listed during #1668 phase 1.
      # user_data only reads the canonical path; the legacy glob covers the
      # six SSM resources still defined at /<env>/nhp/frps/* in
      # blue_green.tf (active-color, green-image-tag, last-switch-timestamp,
      # blue-asg-name, green-asg-name, color-cloudmap-service-ids) so the
      # operator can `aws ssm get-parameter` them from this instance role
      # for ad-hoc debugging. Trade-off: a forgotten consumer reading the
      # legacy path SUCCEEDS silently rather than failing IAM-denied. The
      # blue/green keys have no in-codebase reader today, so the silent-
      # success risk is bounded; the legacy glob is dropped in the same
      # follow-up PR that migrates those keys to the canonical path.
      {
        Sid    = "SSMParameterRead"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/reverse-tunnel-server/*",
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/frps/*",
        ]
      },
      # Cloud Map registration. Do not enumerate concrete service ARNs:
      # that makes the instance profile depend on the ForceNew Cloud Map
      # service resources, and the FRPS ASG's create_before_destroy then
      # propagates into those services in state. Scope by tags instead so
      # service replacement stays destroy-then-create with the stable names.
      # This intentionally broadens from enumerated service IDs to any
      # qurl-reverse-tunnel-server Cloud Map service in this env. Blue/green
      # ASGs share this same instance role, so IAM is not a per-color isolation
      # boundary; user_data's IMDS-derived DEPLOY_COLOR is the color-selection
      # gate.
      {
        Sid    = "CloudMapListServices"
        Effect = "Allow"
        Action = ["servicediscovery:ListServices"]
        # AWS does not support resource-level permissions for ListServices.
        # This grants account-wide enumeration of all Cloud Map services to
        # the FRPS instance role; Register/Deregister remain constrained by
        # tags below.
        Resource = "*"
      },
      {
        Sid    = "CloudMapRegister"
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance"
        ]
        Resource = "arn:aws:servicediscovery:${local.region}:${local.account_id}:service/*"
        Condition = {
          StringEquals = local.frps_cloudmap_required_tag_conditions
        }
      },
      # ECR access (split: GetAuthorizationToken must be * per AWS docs;
      # pull actions scoped to specific repo ARN, consistent with AC module)
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
          "ecr:BatchGetImage"
        ]
        Resource = coalesce(var.frps_ecr_repo_arn, "arn:aws:ecr:${local.region}:${local.account_id}:repository/layerv/qurl-reverse-tunnel-server")
      },
      # ASG launch-readiness gate (qurl-reverse-tunnel-server#195). user_data
      # self-completes the EC2_INSTANCE_LAUNCHING hook after the FRP readiness
      # probe passes, so the instance reaches InService only when serving.
      # CompleteLifecycleAction is scoped to the blue + green frps ASGs. Both
      # colors share this role (color isolation is IMDS-driven, not IAM), so the
      # two ASG-name ARNs are listed explicitly. The `:*:` segment wildcards the
      # ASG's generated UUID; the name suffix is exact.
      {
        Sid    = "ASGCompleteLifecycleAction"
        Effect = "Allow"
        Action = ["autoscaling:CompleteLifecycleAction"]
        Resource = [
          "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/${var.name_prefix}-frps",
          "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/${var.name_prefix}-frps-green",
        ]
      },
      # user_data derives its own ASG name (blue vs green) at boot to target the
      # CompleteLifecycleAction call. DescribeAutoScalingInstances does not
      # support resource-level permissions (AWS returns AccessDenied for a
      # non-`*` resource), so it is account-wide read-only — consistent with the
      # CloudMapListServices `*` grant above.
      {
        Sid      = "ASGDescribeForReadiness"
        Effect   = "Allow"
        Action   = ["autoscaling:DescribeAutoScalingInstances"]
        Resource = "*"
      },
    ]
  })

  lifecycle {
    precondition {
      # IAM evaluates the tags that land on the Cloud Map service resources.
      # Keep this in lockstep with `local.frps_cloudmap_service_tags` and the
      # StringEquals condition above so tag drift fails during plan.
      condition = (
        trimspace(local.frps_cloudmap_required_tags.Environment) != ""
        && alltrue([
          for k, v in local.frps_cloudmap_required_tags :
          trimspace(v) != ""
          && lookup(local.frps_cloudmap_service_tags, k, "") == v
          && lookup(local.frps_cloudmap_required_tag_conditions, "aws:ResourceTag/${k}", "") == v
        ])
      )
      error_message = "qurl-reverse-tunnel-server Cloud Map service tags must include non-empty Environment=${local.frps_cloudmap_required_tags.Environment} and Service=${local.frps_cloudmap_required_tags.Service} because FRPS Register/Deregister IAM evaluates aws_service_discovery_service.frps_per_az resource tags. Omitting either service tag would boot instances into AccessDenied instead of failing at plan time."
    }
  }
}

# Secrets Manager access for QURL/NHP tunnel-auth secrets. CMK-encrypted
# secrets require both `secretsmanager:GetSecretValue` and caller-side
# `kms:Decrypt`; root wires `module.kms.secrets_key_arn` for the shared NHP
# internal auth secret.
resource "aws_iam_role_policy" "frps_secrets" {
  count = var.qurl_api_token_secret_arn != "" || var.nhp_internal_auth_secret_arn != "" ? 1 : 0
  name  = "frps-secrets"
  role  = aws_iam_role.frps.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = compact([
          var.qurl_api_token_secret_arn,
          var.nhp_internal_auth_secret_arn,
        ])
      }
      ],
      var.secrets_kms_key_arn != null ? [{
        Sid      = "SecretsKmsDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
      }] : []
    )
  })
}

# S3 fallback read access for the binary download path in user_data.
# Conditional on the bucket ARN being threaded from root: an empty value
# means "ECR-only, no fallback" (the `aws s3 cp` branch will still fire
# on ECR failure but will AccessDenied, which matches the script's
# existing FATAL behavior). Scoped to the qurl-reverse-tunnel-server subtree of the
# plugins bucket — consistent with how `modules/ac/main.tf:715` scopes
# its own script-download grant. Integrity verification (#1258) layers
# on top of this grant in a follow-up PR.
resource "aws_iam_role_policy" "frps_s3_fallback" {
  count = var.plugin_bucket_arn != "" ? 1 : 0
  name  = "frps-s3-fallback"
  role  = aws_iam_role.frps.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BinaryS3Fallback"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        # The legacy `binaries/qurl-frps/*` prefix is intentionally retained
        # alongside the canonical `binaries/qurl-reverse-tunnel-server/*` for
        # one rebrand-transition cycle. user_data's `aws s3 cp` chain falls
        # back from canonical → legacy on 404; without the legacy grant the
        # fallback would AccessDenied if the publishing pipeline hasn't
        # migrated yet. Drop the legacy entry in lockstep with the user_data
        # legacy branch once at least one cycle of S3 objects under the new
        # prefix has been published.
        Resource = [
          "${var.plugin_bucket_arn}/binaries/qurl-reverse-tunnel-server/*",
          "${var.plugin_bucket_arn}/binaries/qurl-frps/*",
        ]
      }
    ]
  })
}

# Attach the shared plugin-bucket download policy for the S3-hosted bootstrap
# script. The inline frps_s3_fallback policy above intentionally remains scoped
# to the legacy binary fallback prefixes; the shared policy carries the bucket
# KMS decrypt grant required for scripts/frps-init.sh.
resource "aws_iam_role_policy_attachment" "frps_plugins" {
  count = var.plugin_download_policy_arn != "" ? 1 : 0

  role       = aws_iam_role.frps.name
  policy_arn = var.plugin_download_policy_arn
}

resource "aws_s3_object" "frps_init_script" {
  count = var.plugin_bucket_name != "" ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/frps-init.sh"
  content      = local.user_data
  content_type = "text/x-shellscript"
}

# ==================== Security Group ====================

resource "aws_security_group" "frps" {
  name_prefix = "${var.name_prefix}-frps-"
  vpc_id      = var.vpc_id
  description = "Security group for FRP server instances"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-frps"
    Component = "frps"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# FRP control port - ingress from AC security group only
resource "aws_vpc_security_group_ingress_rule" "frps_control" {
  security_group_id            = aws_security_group.frps.id
  description                  = "FRP control channel from AC"
  from_port                    = var.frps_bind_port
  to_port                      = var.frps_bind_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.ac_security_group_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-frps-control"
  })
}

# FRP vhost HTTP port - ingress from AC security group only
resource "aws_vpc_security_group_ingress_rule" "frps_vhost_http" {
  security_group_id            = aws_security_group.frps.id
  description                  = "FRP vhost HTTP from AC"
  from_port                    = var.frps_vhost_http_port
  to_port                      = var.frps_vhost_http_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.ac_security_group_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-frps-vhost-http"
  })
}

# Egress — allow all outbound (FRP server needs to reach customer backends).
#
# Intentional wide egress: a tunnel server's whole purpose is to forward
# traffic to arbitrary customer-designated destinations (port 443 for an
# HTTPS backend, an internal IP for a private app, etc.), so we can't
# enumerate them ahead of time. This mirrors the AC module's egress posture,
# which exists for the same reason (customer backends + ACME + ECR + SSM).
# The defense-in-depth here is the *ingress* side: frps only accepts
# connections from the AC security group, and AC only accepts authenticated
# NHP knocks + Traefik traffic, so a compromised frps doesn't become a
# reachable open-internet pivot.
resource "aws_vpc_security_group_egress_rule" "frps_all" {
  security_group_id = aws_security_group.frps.id
  description       = "All outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-frps-egress"
  })
}

# ==================== Cloud Map Service Discovery (per-AZ) ====================
#
# One Cloud Map service per AZ suffix. qurl-service hashes OwnerID to one of
# these suffixes and emits the matching `frps-${suffix}.${namespace_name}`
# DNS name as `frps_addr` in CreateResource / GetResourceTarget responses,
# so frpc and qurl-router converge on the same instance. See module header
# and #1499 for the full cross-repo contract.
#
# Routing policy: configurable via `var.cloud_map_routing_policy`.
#
# - WEIGHTED   (default, backwards compatible): each query returns ONE
#   A record. Correct for 1-instance-per-AZ; both frpc and qurl-router
#   converge on the per-resource `frps_addr` from the QURL API.
# - MULTIVALUE: each query returns the FULL set of healthy A records
#   (up to 8). Required when running >1 instance per AZ so that
#   router-side HRW (traefik-plugins #134) can resolve the boundary
#   hostname and hash a resource_id to a specific instance IP, and so
#   that frpc can do the same on the dial side.
#
# A precondition below rejects "WEIGHTED + effective desired > N AZ
# suffixes" so a 2/AZ rollout can't ship before the routing flip.
#
# IMPORTANT: AWS Cloud Map's `UpdateService` API does NOT support
# changing `routing_policy` in place — only Description, DnsRecords,
# and HealthCheckConfig.FailureThreshold are mutable. The provider
# therefore marks `dns_config.routing_policy` as ForceNew. Flipping
# `var.cloud_map_routing_policy` from WEIGHTED to MULTIVALUE
# will appear in the plan as REPLACEMENT of every per-AZ
# `aws_service_discovery_service.frps_per_az[*]` resource (and, if
# blue/green is enabled, of every `frps_per_az_green[*]` too):
#   - Each replacement issues new service IDs. Instances resolve those
#     IDs from the stable Cloud Map service names at boot; do not re-add
#     launch-template or IAM dependencies on concrete service IDs.
#   - Existing instance registrations on the old services are dropped
#     when the old services delete; new instances must register with
#     the new services as user_data picks up the new IDs.
#   - The qurl-service `frps_addr` emitter must pick up the new ARNs
#     out-of-band before traffic shifts.
# The runbook needs to sequence these; the blue/green path (sandbox)
# and the canary path (prod) BOTH have to plan for this replacement
# window. Documented here so the requirement isn't discovered at plan time.
resource "aws_service_discovery_service" "frps_per_az" {
  for_each = toset(var.frps_az_suffixes)

  name        = "frps-${each.key}"
  description = "qurl-reverse-tunnel-server — AZ suffix '${each.key}'"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = var.cloud_map_routing_policy
  }

  lifecycle {
    precondition {
      # Catch the dangerous misconfig where WEIGHTED routing is paired with
      # >1 instance per AZ. WEIGHTED returns a single A record per query;
      # the router would see only one of N instances at a time, defeating
      # router-side HRW (traefik-plugins #134) which needs to enumerate
      # the full set of healthy IPs to make a deterministic dispatch
      # decision. Plan-time fence — if you bump `desired_capacity_per_az`
      # to 2 without flipping `cloud_map_routing_policy`, you hit this
      # error on the PR review, not on a half-applied deploy.
      condition     = var.cloud_map_routing_policy == "MULTIVALUE" || local.effective_desired_capacity <= local.az_count
      error_message = "cloud_map_routing_policy = \"WEIGHTED\" only supports up to one instance per AZ (effective desired_capacity ≤ length(frps_az_suffixes)). Got effective desired_capacity = ${local.effective_desired_capacity}, length(frps_az_suffixes) = ${local.az_count}. Flip cloud_map_routing_policy to \"MULTIVALUE\" before raising desired_capacity_per_az above 1 — see traefik-plugins #134 for the router-side HRW that consumes the full A-record set."
    }
  }

  # Custom health check config: registering this block enables Cloud Map to
  # track health state for instances in this service. Without it, Cloud Map
  # has no health-check machinery and keeps stale records indefinitely if an
  # instance OOM-kills frps without a clean systemd shutdown.
  #
  # With this block set, a future UpdateInstanceCustomHealthStatus call
  # (tracked in #1089) can deregister unhealthy instances faster than waiting
  # for the ASG replace cycle. On first boot, user_data verifies FRP is ready
  # before calling cloudmap-register.sh, so only healthy instances ever register.
  #
  # `health_check_custom_config` block deliberately omitted. The
  # provider used to accept `failure_threshold = N` here, but AWS now
  # ignores the value and always uses 1; the provider marks the
  # argument deprecated, surfacing as a `terraform validate` warning
  # and a future hard removal. Cloud Map registrations land healthy on
  # the first user_data registration call (the AWS-side default of 1
  # is correct here), so dropping the block has no behavior change.

  tags = local.frps_cloudmap_service_tags
}

# ==================== Launch Template ====================

resource "aws_launch_template" "frps" {
  name_prefix   = "${var.name_prefix}-frps-"
  image_id      = data.aws_ssm_parameter.ubuntu_ami.insecure_value
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.frps.arn
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.frps.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  user_data = local.frps_launch_template_user_data

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = var.tags

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name      = "${var.name_prefix}-frps"
      Component = "frps"
    })
  }

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = length(base64decode(local.frps_launch_template_user_data)) <= 16384
      error_message = "qurl-reverse-tunnel-server launch-template user_data exceeds EC2's 16384-byte cap. Keep the launch template on the S3 bootstrap pattern and move bulk logic into user_data.sh.tpl / scripts/frps-init.sh."
    }

    precondition {
      condition     = (var.plugin_bucket_name == "") == (var.plugin_download_policy_arn == "")
      error_message = "plugin_bucket_name and plugin_download_policy_arn must be set together — the S3 bootstrap fetch needs both s3:GetObject and the plugin bucket KMS decrypt grant."
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.frps_plugins,
    aws_s3_object.frps_init_script,
  ]
}

# ==================== Auto Scaling Group ====================
# Module default is 1/1/1 so the module is still consumable in isolation,
# but env tfvars override to N/N/N where N == length(frps_az_suffixes) to
# get one instance per AZ at steady state. AWS ASG balances launches
# across distinct subnets-per-AZ; capacity events (ICE in one AZ, instance
# refresh, single-AZ outage) can leave the steady-state distribution
# briefly skewed.
#
# Alarm coverage today: monitoring.tf has `instance_status_check_failed`
# (PAGE: fleet drops below 1 in-service) and `fleet_undersized` (TICKET:
# fleet count < desired_capacity for 15 min). Neither catches *intra-fleet
# AZ skew*: a fleet of 3 with distribution `(a=2, b=1, c=0)` satisfies
# both alarms while `frps-c.${var.namespace_name}` returns NXDOMAIN for
# ~1/3 of OwnerIDs. Two coverage layers exist for that bug class:
#
#   - Detection: an empty-AZ alarm (synthetic DNS canary or per-service
#     `DiscoverInstances` Lambda) tracked in #1542. Catches the skew
#     within a few minutes of it occurring; cheap to ship.
#   - Structural fence: an ASG-per-AZ refactor (one ASG pinned to one
#     subnet, each `min=max=desired=1`) eliminates the bug class entirely
#     by removing single-ASG distribution from the picture. Larger
#     refactor; tracked under parent #1499 (no PR filed yet).
#
# Deploy gating policy:
#   - Sandbox flip (`deploy_frps = true`, see #1544): #1542 is the minimum
#     bar — the alarm is the only fence between an `(a=2,b=1,c=0)`
#     rebalance and silent NXDOMAIN, but blast radius is sandbox-only and
#     #1542 surfaces the skew within minutes.
#   - Prod flip: requires the ASG-per-AZ refactor in addition to #1542.
#     Detection-only is acceptable for a single-env burn-in; it is not
#     acceptable for production where the failure mode is silent
#     ~1/N customer-traffic loss.

resource "aws_autoscaling_group" "frps" {
  name                = "${var.name_prefix}-frps"
  vpc_zone_identifier = var.private_subnet_ids
  # Effective sizing resolved from per-AZ vars when set, falling back to
  # the legacy explicit triple. See `local.effective_*` in main.tf locals.
  min_size         = local.effective_min_size
  max_size         = local.effective_max_size
  desired_capacity = local.effective_desired_capacity

  launch_template {
    id      = aws_launch_template.frps.id
    version = aws_launch_template.frps.latest_version
  }

  # Instance refresh currently gates on EC2 health plus instance_warmup, not
  # FRPS protocol readiness. The stricter Cloud Map/custom health gate remains
  # tracked in #1089; until then, keep warmup above bounded bootstrap time and
  # use auto_rollback so EC2-level refresh failures revert instead of parking
  # the fleet half-rolled. Refresh-launched instances use instance_warmup for
  # this gate, so keep it in lockstep with health_check_grace_period unless the
  # bootstrap/readiness budget is re-evaluated.
  health_check_type         = "EC2"
  health_check_grace_period = 180

  enabled_metrics = local.asg_enabled_metrics

  # qurl-reverse-tunnel-server's runtime contract is launch-template owned:
  # user_data writes the env file, fetches the S3 bootstrap script, and pins
  # the NHP/qurl-service auth wiring. A plain Terraform apply updates the
  # launch template but leaves existing instances on their old env forever
  # unless a separate image-publish workflow happens to refresh the ASG. That
  # is not a valid steady-state dependency: NHP-only changes such as
  # NHP_SERVER_INTERNAL_URL must roll the fleet themselves.
  #
  # Use a launch-first, one-at-a-time refresh so a template-only deploy does
  # not intentionally drop tunnel capacity or force the whole multi-tenant
  # tunnel fleet through a reconnect storm. The temporary +1 surge is the swap
  # window AWS needs to replace instances while min_healthy stays at 100%;
  # 100/200 is also AWS's maximum allowed percentage spread, so it favors
  # availability over refresh speed and accepts the bounded cost surge.
  # The empty-AZ watchdog still covers the single-ASG distribution risk; the
  # longer-term per-AZ ASG refactor remains the structural fix for AZ skew, but
  # this closes the stale user_data/env failure mode without waiting for an
  # image publish.
  #
  # Deliberately omit triggers = ["tag"]: tag-only edits such as DeployColor
  # must not churn tunnel capacity. The default launch-template trigger is the
  # runtime-bearing signal here.
  #
  # When #1499 splits this into one ASG per AZ with min=max=desired=1, preserve
  # the launch-first shape with max_healthy_percentage=200 (or explicitly
  # accept a brief 0-healthy tradeoff). Returning to 100/100 gives AWS no swap
  # window and can deadlock instance refresh.
  instance_refresh {
    strategy = "Rolling"

    preferences {
      instance_warmup        = 180
      min_healthy_percentage = 100
      max_healthy_percentage = 200
      auto_rollback          = true
      skip_matching          = true
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-frps"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "frps"
    propagate_at_launch = true
  }

  # DeployColor: only emitted when blue/green is enabled so a fleet that
  # has never run blue/green doesn't see a benign-but-churn-y ASG diff
  # to add the tag. user_data's `DEPLOY_COLOR` defaults to "blue" when
  # the IMDS instance tag is absent, so the missing-tag and
  # tag="blue" cases are equivalent at runtime.
  dynamic "tag" {
    for_each = var.enable_blue_green ? [1] : []
    content {
      key                 = "DeployColor"
      value               = "blue"
      propagate_at_launch = true
    }
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    # CI/CD manages capacity during blue/green switches and canary
    # rollouts; ignore `desired_capacity`/`min_size` here so a Terraform
    # plan after a flip doesn't try to revert it. Matches the AC module
    # pattern (`modules/ac/main.tf:1022`) and the green-side
    # `aws_autoscaling_group.frps_green` block in `blue_green.tf`.
    #
    # The cr-flagged scenario this closes: after a blue→green flip, CI
    # scales the (now-standby) blue ASG down. Without `ignore_changes`,
    # the next `terraform apply` would plan to revert blue back to
    # `local.effective_desired_capacity` and fight CI on every plan.
    #
    # **Deliberate behavior change for non-BG/non-canary deploys.**
    # `lifecycle.ignore_changes` does not accept dynamic content, so
    # this block applies even when both `enable_blue_green = false` AND
    # `enable_qurl_reverse_tunnel_server_canary = false`. In that
    # regime the Terraform initial value is what CI would also set, so
    # it's a no-op AT FIRST APPLY — but until this PR a manual `aws
    # autoscaling update-auto-scaling-group` (or unrelated workflow)
    # would be reverted on the next plan. Starting with this PR, an
    # operator-side change wins until something else flips it back.
    # Matches the AC module's existing posture (`modules/ac/main.tf:1022`
    # has the same unconditional `ignore_changes`); this is the
    # project's deliberate policy for ASGs whose capacity is co-owned
    # by Terraform-at-create and CI-at-deploy.
    ignore_changes = [desired_capacity, min_size]

    precondition {
      # If a QURL API token is configured, the API URL must also be set.
      # Otherwise the instance boots with a valid token but an empty
      # QURL_API_URL, which silently misconfigures the FRP auth plugin.
      condition     = var.qurl_api_token_secret_arn == "" || var.qurl_api_internal_url != ""
      error_message = "qurl_api_internal_url must be set when qurl_api_token_secret_arn is configured — otherwise the FRP auth plugin has a token but no URL to validate against."
    }

    precondition {
      # tunnel-auth mode requires the internal-service shared secret. The
      # user_data token-fetch + JSON/whitespace/empty-string validation
      # block is gated on qurl_api_token_secret_arn != "", so a caller that
      # opts into tunnel-auth without a token ARN would skip every check
      # and write QURL_INTERNAL_SERVICE_TOKEN= (empty) to the env. The
      # qurl-reverse-tunnel-server resolver then can't authenticate /internal/v1/tunnel/auth-by-owner
      # calls, surfacing as opaque 401s at runtime — fail at plan time
      # instead, mirroring the qurl_api_internal_url precondition above.
      #
      # Transitively requires qurl_api_internal_url too: forcing the token
      # ARN non-empty here triggers the precondition above, which in turn
      # demands the URL. So tunnel-auth mode is fenced against both an
      # empty token AND an empty URL without an explicit third check here.
      condition     = var.qurl_tunnel_auth_mode != "tunnel-auth" || var.qurl_api_token_secret_arn != ""
      error_message = "qurl_tunnel_auth_mode = \"tunnel-auth\" requires qurl_api_token_secret_arn — the tunnel-auth resolver still needs the internal-service shared secret to call qurl-service /internal/v1/tunnel/auth-by-owner."
    }

    precondition {
      condition     = var.qurl_tunnel_auth_mode != "tunnel-auth" || var.nhp_server_internal_url != ""
      error_message = "qurl_tunnel_auth_mode = \"tunnel-auth\" requires nhp_server_internal_url so qurl-reverse-tunnel-server can validate AC-issued knock tokens with nhp-server."
    }

    precondition {
      condition     = var.qurl_tunnel_auth_mode != "tunnel-auth" || var.nhp_internal_auth_secret_arn != ""
      error_message = "qurl_tunnel_auth_mode = \"tunnel-auth\" requires nhp_internal_auth_secret_arn so qurl-reverse-tunnel-server can sign knock-token validation requests."
    }

    precondition {
      condition     = var.qurl_tunnel_auth_mode != "tunnel-auth" || var.connect_layerv_host != ""
      error_message = "qurl_tunnel_auth_mode = \"tunnel-auth\" requires connect_layerv_host so active-registration boundary labels map back to the public NHP-protected ingress."
    }

    precondition {
      condition     = var.qurl_tunnel_auth_mode != "tunnel-auth" || length(setsubtract(toset(var.frps_az_suffixes), toset(keys(var.tunnel_server_az_control_ports)))) == 0
      error_message = "qurl_tunnel_auth_mode = \"tunnel-auth\" requires tunnel_server_az_control_ports to include every configured frps_az_suffix so active registrations can report the public NHP-protected control boundary."
    }

    precondition {
      condition     = var.qurl_tunnel_auth_mode != "tunnel-auth" || length(var.tunnel_server_az_control_ports) > 0
      error_message = "qurl_tunnel_auth_mode = \"tunnel-auth\" requires a non-empty tunnel_server_az_control_ports map."
    }

    precondition {
      # All three ports must be distinct: bind (control), vhost HTTP, and the
      # localhost dashboard. Overlapping would cause frps to fail to start
      # with a confusing bind-address-in-use error instead of a plan-time
      # rejection.
      condition     = length(toset([var.frps_bind_port, var.frps_vhost_http_port, var.frps_dashboard_port])) == 3
      error_message = "frps_bind_port, frps_vhost_http_port, and frps_dashboard_port must all be distinct — frps binds each independently."
    }

    precondition {
      # min <= desired <= max on the EFFECTIVE values, regardless of which
      # form (legacy triple or per-AZ vars) supplied them. Catches tfvars
      # typos at plan time rather than letting the ASG API reject them
      # in the middle of an apply. A half-mix during a migration plan
      # (e.g., per-AZ desired set, per-AZ min unset) hits this same
      # error path because the locals fall back to the legacy var
      # whose default is 1.
      condition     = local.effective_min_size <= local.effective_desired_capacity && local.effective_desired_capacity <= local.effective_max_size
      error_message = "qurl-reverse-tunnel-server ASG effective sizing must satisfy min_size <= desired_capacity <= max_size. Resolved: min=${local.effective_min_size}, desired=${local.effective_desired_capacity}, max=${local.effective_max_size}. (Per-AZ vars × length(frps_az_suffixes) when set; legacy triple otherwise.)"
    }

    precondition {
      # Module-level mirror of the root-level half-mix fence in
      # terraform/main.tf::frps_preconditions. The root fence catches
      # the typo for callers that compose this module via root tfvars;
      # this mirror catches module-direct consumers (smoke fixtures,
      # isolated tests, future module reuse). Without it, a half-mix
      # like `desired_capacity_per_az = 2` paired with
      # `min_size_per_az = null` silently falls back to `var.min_size`
      # (default 1) for the unset half, breaks the fixed-size guarantee,
      # and produces the more generic min<=desired<=max failure above
      # rather than an actionable "pick one form fully" message.
      condition = (
        var.desired_capacity_per_az != null
        ? (
          var.min_size_per_az != null
          && var.max_size_per_az != null
          && var.min_size_per_az == var.desired_capacity_per_az
          && var.max_size_per_az == var.desired_capacity_per_az
        )
        : (
          var.min_size_per_az == null
          && var.max_size_per_az == null
        )
      )
      error_message = "Pick exactly one ASG-sizing form: per-AZ form requires ALL THREE of {min_size_per_az, max_size_per_az, desired_capacity_per_az} to be set AND equal; legacy form requires *_per_az to be null AND uses {min_size, max_size, desired_capacity}. Half-mixes (e.g., only desired_capacity_per_az set) silently fall back to legacy `min_size` for the unset half."
    }
  }
}

# EC2_INSTANCE_LAUNCHING readiness hook for the blue frps ASG
# (qurl-reverse-tunnel-server#195). Holds a launching/refreshed instance in
# Pending:Wait (NOT InService) until user_data signals after the FRP readiness
# probe passes, so ASG-health consumers (the post-deploy smoke) never select a
# still-starting box. Separate resource (PutLifecycleHook) rather than the ASG's
# `initial_lifecycle_hook`: the frps ASG is fixed-name and long-lived, so an
# inline initial hook would only attach at ASG *creation* and be a no-op on the
# existing fleet. This shares only the separate-resource *shape* with the compute
# module's `aws_autoscaling_lifecycle_hook.termination`; the completion mechanism
# is new — compute completes its TERMINATING hook via SNS/EventBridge -> Lambda,
# whereas this LAUNCHING hook is self-completed by the instance's user_data (no
# notification_target_arn/role_arn, no Lambda), since the instance is the sole
# authority on its own readiness. The IAM grant above scopes that self-complete.
resource "aws_autoscaling_lifecycle_hook" "frps_launch" {
  name                   = local.frps_launch_lifecycle_hook_name
  autoscaling_group_name = aws_autoscaling_group.frps.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
  default_result         = var.frps_launch_readiness_default_result
  heartbeat_timeout      = var.frps_launch_readiness_heartbeat_timeout
}

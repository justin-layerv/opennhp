mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      region = "us-east-2"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "767397897469"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id           = "ami-0123456789abcdef0"
      architecture = "x86_64"
    }
  }

  mock_resource "aws_eip" {
    defaults = {
      id        = "eipalloc-0123456789abcdef0"
      public_ip = "198.51.100.42"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-2:767397897469:key/11111111-2222-3333-4444-555555555555"
      key_id = "11111111-2222-3333-4444-555555555555"
    }
  }

  mock_resource "aws_launch_template" {
    defaults = {
      id             = "lt-0123456789abcdef0"
      arn            = "arn:aws:ec2:us-east-2:767397897469:launch-template/lt-0123456789abcdef0"
      latest_version = 7
    }
  }

  mock_resource "aws_lambda_function" {
    defaults = {
      arn           = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-udp-proof-runner-broker"
      function_name = "layerv-nhp-sandbox-udp-proof-runner-broker"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-udp-proof-mock"
    }
  }

  mock_resource "aws_iam_instance_profile" {
    defaults = {
      arn = "arn:aws:iam::767397897469:instance-profile/layerv-nhp-sandbox-udp-proof-runner"
    }
  }

  mock_resource "aws_cloudwatch_event_rule" {
    defaults = {
      arn  = "arn:aws:events:us-east-2:767397897469:rule/layerv-nhp-sandbox-udp-proof-runner-sweep"
      name = "layerv-nhp-sandbox-udp-proof-runner-sweep"
    }
  }
}

variables {
  environment              = "sandbox"
  name_prefix              = "layerv-nhp-sandbox"
  vpc_cidr                 = "10.103.0.0/28"
  availability_zone        = "us-east-2a"
  ami_id                   = "ami-0123456789abcdef0"
  github_oidc_provider_arn = "arn:aws:iam::767397897469:oidc-provider/token.actions.githubusercontent.com"
  runner_archive_url       = "https://github.com/actions/runner/releases/download/v2.999.1/actions-runner-linux-x64-2.999.1.tar.gz"
  runner_archive_sha256    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  proof_kms_key_arns = [
    "arn:aws:kms:us-east-2:767397897469:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "arn:aws:kms:us-east-2:767397897469:key/11111111-aaaa-bbbb-cccc-222222222222",
  ]
}

run "secure_ephemeral_runner_contract" {
  command = apply

  assert {
    condition = (
      aws_vpc.runner.cidr_block == "10.103.0.0/28" &&
      aws_vpc.runner.enable_dns_hostnames &&
      aws_vpc.runner.enable_dns_support &&
      aws_vpc.runner.enable_network_address_usage_metrics &&
      aws_subnet.runner.cidr_block == "10.103.0.0/28" &&
      !aws_subnet.runner.map_public_ip_on_launch &&
      aws_route.public.destination_cidr_block == "0.0.0.0/0"
    )
    error_message = "The runner must stay in its dedicated public /28 with no automatic public-IP allocation."
  }

  assert {
    condition = (
      length(aws_security_group.runner.ingress) == 0 &&
      length(aws_security_group.runner.egress) == 0 &&
      toset([
        aws_vpc_security_group_egress_rule.dns_udp.ip_protocol,
        aws_vpc_security_group_egress_rule.dns_tcp.ip_protocol,
        aws_vpc_security_group_egress_rule.https.ip_protocol,
        aws_vpc_security_group_egress_rule.nhp_udp.ip_protocol,
        aws_vpc_security_group_egress_rule.time_sync.ip_protocol,
      ]) == toset(["tcp", "udp"]) &&
      aws_vpc_security_group_egress_rule.dns_udp.cidr_ipv4 == "10.103.0.2/32" &&
      aws_vpc_security_group_egress_rule.dns_udp.from_port == 53 &&
      aws_vpc_security_group_egress_rule.dns_tcp.from_port == 53 &&
      aws_vpc_security_group_egress_rule.https.from_port == 443 &&
      aws_vpc_security_group_egress_rule.nhp_udp.cidr_ipv4 == "0.0.0.0/0" &&
      aws_vpc_security_group_egress_rule.nhp_udp.from_port == 62206 &&
      aws_vpc_security_group_egress_rule.time_sync.cidr_ipv4 == "169.254.169.123/32" &&
      aws_vpc_security_group_egress_rule.time_sync.from_port == 123
    )
    error_message = "The runner SG must have no ingress/inline egress and exactly the DNS, HTTPS, NHP UDP, and time-sync egress contract."
  }

  assert {
    condition = (
      aws_eip.source.domain == "vpc" &&
      aws_launch_template.runner.network_interfaces[0].subnet_id == aws_subnet.runner.id &&
      toset(aws_launch_template.runner.network_interfaces[0].security_groups) == toset([aws_security_group.runner.id]) &&
      !aws_launch_template.runner.network_interfaces[0].associate_public_ip_address &&
      aws_launch_template.runner.network_interfaces[0].delete_on_termination &&
      output.stable_source_ipv4 == "198.51.100.42" &&
      output.stable_source_cidr == "198.51.100.42/32"
    )
    error_message = "One persistent EIP must provide the stable allowlisted /32 while each runner receives a delete-on-termination ENI with no dynamic public IP."
  }

  assert {
    condition = (
      aws_launch_template.runner.instance_initiated_shutdown_behavior == "terminate" &&
      aws_launch_template.runner.instance_type == "m7i.large" &&
      aws_launch_template.runner.image_id == data.aws_ami.runner.id &&
      data.aws_ami.runner.architecture == "x86_64" &&
      aws_launch_template.runner.block_device_mappings[0].ebs[0].encrypted &&
      aws_launch_template.runner.block_device_mappings[0].ebs[0].delete_on_termination &&
      aws_launch_template.runner.metadata_options[0].http_tokens == "required" &&
      aws_launch_template.runner.metadata_options[0].http_put_response_hop_limit == 2 &&
      aws_launch_template.runner.metadata_options[0].instance_metadata_tags == "enabled"
    )
    error_message = "The exact launch template must terminate on shutdown, encrypt/delete storage, and require container-compatible IMDSv2 with tags."
  }

  assert {
    condition = (
      strcontains(base64decode(aws_launch_template.runner.user_data), "systemctl enable --now udp-proof-deadline.timer") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "s|http://|https://|g") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "docker.io") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "iproute2") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "tcpdump") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "retry_command apt-get -o Acquire::Retries=4 update") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "retry_command /opt/actions-runner/bin/installdependencies.sh") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "imds_token=\"$(retry_command curl") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "X-aws-ec2-metadata-token-ttl-seconds: 300") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "github_run_id=\"$(retry_command curl") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "github_run_attempt=\"$(retry_command curl") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "setcap cap_net_admin,cap_net_raw=eip") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "GitHubRunAttempt") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "retry_command fetch_jit_config") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "retry_command delete_jit_secret") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "mv /run/udp-proof/jitconfig.tmp /run/udp-proof/jitconfig") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "--cli-connect-timeout 10") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "--cli-read-timeout 30") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "ResourceNotFoundException") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "./run.sh --jitconfig") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "secretsmanager delete-secret")
    )
    error_message = "Bootstrap must install the required tooling, delete the JIT secret, run one JIT job, and arm independent termination."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:layervai/nhp:environment:udp-proof-sandbox" &&
      jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    )
    error_message = "Controller OIDC trust must be exact-repository and exact-protected-environment scoped."
  }

  assert {
    condition = (
      strcontains(file("${path.module}/README.md"), "restricted to exactly private") &&
      strcontains(file("${path.module}/README.md"), "`layervai/qurl-connector` plus public `layervai/qurl-go`") &&
      strcontains(file("${path.module}/README.md"), "`allows_public_repositories=true` is unavoidable") &&
      strcontains(file("${path.module}/README.md"), "bind and read back") &&
      strcontains(file("${path.module}/README.md"), "Fail before minting a JIT configuration") &&
      strcontains(file("${path.module}/README.md"), "visibility=selected") &&
      strcontains(file("${path.module}/README.md"), "NHP repository must not be granted") &&
      strcontains(file("${path.module}/README.md"), "restricted_to_workflows=true") &&
      strcontains(file("${path.module}/README.md"), "sandbox-smoke.yml@<exact signed Connector candidate commit>") &&
      strcontains(file("${path.module}/README.md"), "native-udp-sandbox.yml@<exact signed qurl-go candidate commit>") &&
      strcontains(file("${path.module}/README.md"), "later controller/composition PR pins those three values") &&
      strcontains(file("${path.module}/README.md"), "candidate digest from the trusted-main canary workflow") &&
      strcontains(file("${path.module}/README.md"), "clients reach their final reviewed proof heads") &&
      strcontains(file("${path.module}/README.md"), "Fork, pull-request, and unreviewed jobs therefore") &&
      strcontains(file("${path.module}/README.md"), "`nhp_controller_run_id` and `nhp_controller_run_attempt`") &&
      strcontains(file("${path.module}/README.md"), "[1-9][0-9]{0,19}") &&
      strcontains(file("${path.module}/README.md"), "[1-9][0-9]{0,9}") &&
      strcontains(file("${path.module}/README.md"), "preconstructed `runner_label` input") &&
      strcontains(file("${path.module}/README.md"), "both controller inputs into the proof") &&
      strcontains(file("${path.module}/README.md"), "compromised client transitive") &&
      strcontains(file("${path.module}/README.md"), "process lifetime") &&
      strcontains(file("${path.module}/README.md"), "sustained `DescribeAddresses` failure") &&
      strcontains(file("${path.module}/README.md"), "Use two separate, attended NHP controller runs") &&
      strcontains(file("${path.module}/README.md"), "connector_proof_run_id") &&
      !strcontains(file("${path.module}/README.md"), "runner group restricted to the NHP repository")
    )
    error_message = "The composition contract must keep NHP as controller-only and bind the organization JIT runners to exact Connector/qurl-go workflows in two serialized client proofs."
  }

  assert {
    condition = (
      toset([for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid]) == toset([
        "CreateOneTimeJITConfiguration",
        "TagOneTimeJITConfiguration",
        "PrepareOneTimeJITEncryption",
        "InvokeBoundedRunnerBroker",
      ]) &&
      !strcontains(aws_iam_role_policy.controller.policy, "ec2:") &&
      !strcontains(aws_iam_role_policy.controller.policy, "secretsmanager:GetSecretValue") &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateOneTimeJITConfiguration"].Action == "secretsmanager:CreateSecret" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateOneTimeJITConfiguration"].Condition.StringEquals["secretsmanager:KmsKeyArn"] == aws_kms_key.jit.arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateOneTimeJITConfiguration"].Condition.StringEquals["aws:RequestTag/Environment"] == var.environment &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateOneTimeJITConfiguration"].Condition.StringEquals["aws:RequestTag/Purpose"] == "udp-proof" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateOneTimeJITConfiguration"].Condition["ForAllValues:StringEquals"]["aws:TagKeys"]) == toset(["Environment", "Purpose", "GitHubRunId", "GitHubRunAttempt"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateOneTimeJITConfiguration"].Condition.Null["aws:RequestTag/GitHubRunId"] == "false" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateOneTimeJITConfiguration"].Condition.Null["aws:RequestTag/GitHubRunAttempt"] == "false" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["TagOneTimeJITConfiguration"].Action == "secretsmanager:TagResource" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["TagOneTimeJITConfiguration"].Condition.StringEquals["aws:RequestTag/Environment"] == var.environment &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["TagOneTimeJITConfiguration"].Condition.StringEquals["aws:RequestTag/Purpose"] == "udp-proof" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["TagOneTimeJITConfiguration"].Condition["ForAllValues:StringEquals"]["aws:TagKeys"]) == toset(["Environment", "Purpose", "GitHubRunId", "GitHubRunAttempt"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["TagOneTimeJITConfiguration"].Condition.Null["aws:RequestTag/GitHubRunId"] == "false" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["TagOneTimeJITConfiguration"].Condition.Null["aws:RequestTag/GitHubRunAttempt"] == "false" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["PrepareOneTimeJITEncryption"].Action == "kms:GenerateDataKey"
    )
    error_message = "The workflow controller must create exactly tagged, dedicated-key JIT metadata and invoke the broker; it gets no EC2 or secret-read surface."
  }

  assert {
    condition = (
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["LaunchExactTemplate"].Condition.ArnEquals["ec2:LaunchTemplate"] == aws_launch_template.runner.arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["LaunchExactTemplate"].Condition.Bool["ec2:IsLaunchTemplateResource"] == "true" &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["AttachDedicatedSourceAddress"].Action == "ec2:AssociateAddress" &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["PassOnlyProofRunnerRole"].Resource == aws_iam_role.runner.arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["PassOnlyProofRunnerRole"].Condition.StringEquals["iam:PassedToService"] == "ec2.amazonaws.com"
    )
    error_message = "Only the broker may launch the exact template, attach the dedicated EIP, and pass the exact runner role to EC2."
  }

  assert {
    condition = (
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DescribeProofKeys"].Resource) == var.proof_kms_key_arns &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DecryptBoundConnectorState"].Resource) == var.proof_kms_key_arns &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DecryptBoundConnectorState"].Action == "kms:Decrypt" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DecryptBoundConnectorState"].Condition.StringEquals["kms:EncryptionContext:purpose"] == "qurl-agent-x25519-private-key" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DecryptBoundConnectorState"].Condition.StringEquals["kms:EncryptionContext:provider"]) == toset(["aws-kms", "aws-nitro"])
    )
    error_message = "Proof KMS access must be exact-key Describe/Decrypt only and encryption-context bound to Connector sealed state."
  }

  assert {
    condition = (
      aws_lambda_function.broker.reserved_concurrent_executions == 1 &&
      aws_lambda_function.broker.timeout == 30 &&
      aws_lambda_function.broker.logging_config[0].log_format == "Text" &&
      aws_lambda_function.broker.logging_config[0].log_group == aws_cloudwatch_log_group.broker.name &&
      aws_lambda_function.broker.environment[0].variables.EIP_ALLOCATION_ID == aws_eip.source.id &&
      aws_cloudwatch_event_rule.sweep.schedule_expression == "rate(5 minutes)" &&
      aws_lambda_permission.events.principal == "events.amazonaws.com"
    )
    error_message = "The broker must serialize launch/cleanup and retain its independent five-minute sweep."
  }
}

run "reject_cross_account_proof_key" {
  command = plan

  variables {
    proof_kms_key_arns = [
      "arn:aws:kms:us-east-2:111122223333:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    ]
  }

  expect_failures = [aws_iam_role_policy.runner]
}

run "reject_noncanonical_ami_length" {
  command = plan

  variables {
    ami_id = "ami-012345678"
  }

  expect_failures = [var.ami_id]
}

run "accept_legacy_ami_length" {
  command = plan

  variables {
    ami_id = "ami-01234567"
  }
}

run "reject_non_x86_64_ami" {
  command = plan

  override_data {
    target = data.aws_ami.runner
    values = {
      id           = "ami-0123456789abcdef0"
      architecture = "arm64"
    }
  }

  expect_failures = [aws_launch_template.runner]
}

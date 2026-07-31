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

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::767397897469:policy/layerv-nhp-sandbox-udp-proof-mock"
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

mock_provider "external" {
  mock_data "external" {
    defaults = {
      result = {
        name = ""
      }
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
  runtime_attestation_bucket_arn       = "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestations"
  runtime_attestation_kms_key_arn      = "arn:aws:kms:us-east-2:767397897469:key/33333333-aaaa-bbbb-cccc-444444444444"
  provisioned_cell_catalog_kms_key_arn = "arn:aws:kms:us-east-2:767397897469:key/55555555-aaaa-bbbb-cccc-666666666666"
  proof_account_credential_sha256      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  proof_mailbox_route53_zone_id        = "Z10394893FM38A1RXLL32"
  proof_mailbox_domain                 = "proof.notify.layerv.xyz"
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
      # The connector proof runs `make frpc` to build its client binary, which
      # failed with exit 127 (make: command not found) once the earlier missing
      # tools were fixed.
      strcontains(base64decode(aws_launch_template.runner.user_data), "make") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "tcpdump") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "tee /dev/console | logger --tag udp-proof-bootstrap") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "retry_command apt-get -o Acquire::Retries=4 update") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "awscli-exe-linux-x86_64-2.36.11.zip") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "50fbb7a2f44a78eab4a210088040e8f0bc4b9937cac8043c2354269d58614df6") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "awscliv2.zip") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "sha256sum --check --strict") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "/aws/install") &&
      # The proof workflows shell out to `gh`, which Ubuntu 24.04 does not ship.
      # A missing binary failed the attended proof at "Verify exact proof
      # inputs" with exit 127, so pin it by checksum like the AWS CLI above.
      strcontains(base64decode(aws_launch_template.runner.user_data), "cli/cli/releases/download/v2.83.0") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "a5cf6cdb40fc67751adf561126b3314044779cea81ba4f254fbe8e9a69f1676f") &&
      strcontains(base64decode(aws_launch_template.runner.user_data), "install -m 0755 /run/udp-proof/gh_2.83.0_linux_amd64/bin/gh /usr/local/bin/gh") &&
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
      jsondecode(aws_iam_role.manifest_producer.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:layervai/nhp:environment:udp-proof-manifest-sandbox" &&
      jsondecode(aws_iam_role.manifest_producer.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com" &&
      output.manifest_producer_role_arn == aws_iam_role.manifest_producer.arn
    )
    error_message = "The manifest producer must have its own exact protected-environment OIDC trust and output."
  }

  assert {
    condition = (
      toset([for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid]) == toset([
        "ReadExactPublicRuntimeParameters",
        "DescribeExactProofKeys",
        "ReadExactRepairDocument",
        "ReadProvisionedCellCatalog",
        "ReadExactRuntimeImages",
        "ReadECRAuthorizationToken",
        "ReadExactAuthorityFunctions",
        "ReadExactECSDeployments",
        "DescribeExactECSTasks",
        "ListExactECSTasks",
        "ReadExactECSTaskDefinitions",
        "ReadExactInstanceProfiles",
        "ReadExactPublicDNSZone",
        "ReadRegionalFleetTopology",
        "ConfirmSandboxIdentity",
      ]) &&
      !strcontains(aws_iam_role_policy.manifest_producer_core.policy, "secretsmanager:") &&
      !strcontains(aws_iam_role_policy.manifest_producer_core.policy, "kms:Decrypt") &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["DescribeExactProofKeys"].Action == "kms:DescribeKey" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["DescribeExactProofKeys"].Resource) == var.proof_kms_key_arns &&
      !strcontains(aws_iam_role_policy.manifest_producer_core.policy, "ssm:GetParametersByPath") &&
      # Pin the exact parameter SET, not just its cardinality. A bare count
      # accepts a renamed or wrong-cell parameter, which is precisely the class
      # of mistake that produces an AccessDenied reading as missing
      # infrastructure. The two cells are resolved by ACTIVE COLOUR:
      # <env>/nhp/server/active-color selects <env>/nhp/server/<colour>-asg-name.
      # <env>/nhp/server/asg-name is deliberately absent -- it is the
      # colour-blind base/blue group modules/compute publishes for CI/CD
      # instance refreshes, and granting it invites the colour-blind read back.
      toset(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactPublicRuntimeParameters"].Resource) == toset([
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/control/hub/identity/public-key",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/udp-proof/runtime-attestation-bucket-arn",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/udp-proof/runtime-attestation-collector-contract",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/server/active-color",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/server/blue-asg-name",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/server/green-asg-name",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox-cell1/nhp/server/active-color",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox-cell1/nhp/server/blue-asg-name",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox-cell1/nhp/server/green-asg-name",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/reverse-tunnel-server/asg-name",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/qurl/relay-url",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/qurl-service/runtime-contract",
        "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox-cell1/nhp/qurl-service/runtime-contract",
      ]) &&
      !strcontains(aws_iam_role_policy.manifest_producer_core.policy, "parameter/sandbox/nhp/server/asg-name") &&
      !strcontains(aws_iam_role_policy.manifest_producer_core.policy, "parameter/sandbox-cell1/nhp/server/asg-name") &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactRepairDocument"].Resource == "arn:aws:ssm:us-east-2:767397897469:document/layerv-nhp-sandbox-runtime-attestation-repair" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadProvisionedCellCatalog"].Action == "dynamodb:GetItem" &&
      length(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactRuntimeImages"].Resource) == 5 &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactRuntimeImages"].Action) == toset(["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadECRAuthorizationToken"].Action == "ecr:GetAuthorizationToken" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadECRAuthorizationToken"].Condition.StringEquals["aws:RequestedRegion"] == "us-east-2" &&
      length(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactAuthorityFunctions"].Resource) == 26 &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactECSDeployments"].Resource) == toset([
        "arn:aws:ecs:us-east-2:767397897469:service/layerv-nhp-sandbox-control-hub/layerv-nhp-sandbox-control-hub",
        "arn:aws:ecs:us-east-2:767397897469:service/layerv-nhp-sandbox-cell0-qurl-api/layerv-nhp-sandbox-cell0-qurl-api",
        "arn:aws:ecs:us-east-2:767397897469:service/layerv-nhp-sandbox-cell1-qurl-api/layerv-nhp-sandbox-cell1-qurl-api",
      ]) &&
      length(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["DescribeExactECSTasks"].Resource) == 3 &&
      length(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["DescribeExactECSTasks"].Condition.ArnEquals["ecs:cluster"]) == 3 &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ListExactECSTasks"].Resource == "*" &&
      length(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ListExactECSTasks"].Condition.ArnEquals["ecs:cluster"]) == 3 &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactECSTaskDefinitions"].Resource == "*" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadExactECSTaskDefinitions"].Condition.StringEquals["aws:RequestedRegion"] == "us-east-2" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadRegionalFleetTopology"].Action) == toset([
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeInstanceRefreshes",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "ssm:DescribeAssociation",
        "ssm:DescribeAssociationExecutions",
        "ssm:DescribeAssociationExecutionTargets",
      ]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_core.policy).Statement : statement.Sid => statement })["ReadRegionalFleetTopology"].Condition.StringEquals["aws:RequestedRegion"] == "us-east-2"
    )
    error_message = "The manifest producer core policy must remain read-only and exact-resource scoped wherever AWS supports it."
  }

  assert {
    condition = (
      length(aws_iam_role_policy.manifest_producer_attestations) == 1 &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["ReadAttestationBucketControls"].Resource == var.runtime_attestation_bucket_arn &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["ReadAttestationBucketControls"].Action) == toset(["s3:GetEncryptionConfiguration", "s3:GetBucketOwnershipControls", "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetBucketVersioning"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["ListVersionedRuntimeAttestations"].Condition.StringLike["s3:prefix"] == "runtime/*" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["ReadImmutableRuntimeAttestationVersions"].Action == "s3:GetObjectVersion" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["DecryptOnlyAttestationObjects"].Resource == var.runtime_attestation_kms_key_arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["DecryptOnlyAttestationObjects"].Condition.StringEquals["kms:ViaService"] == "s3.us-east-2.amazonaws.com" &&
      # S3 Bucket Keys (required by the collector contract) put the bucket ARN
      # in the KMS encryption context, so an object-scoped context can never
      # match. The runtime/ prefix stays enforced on s3:GetObjectVersion above.
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["DecryptOnlyAttestationObjects"].Condition.StringEquals["kms:EncryptionContext:aws:s3:arn"] == var.runtime_attestation_bucket_arn &&
      !can(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_attestations[0].policy).Statement : statement.Sid => statement })["DecryptOnlyAttestationObjects"].Condition.ArnLike)
    )
    error_message = "Runtime-attestation access must be version-only, prefix-scoped, and exact-key/context bound."
  }

  assert {
    condition = (
      length(aws_iam_role_policy.manifest_producer_catalog_decrypt) == 1 &&
      # Exactly one statement: the catalog decrypt is its own policy so the core
      # policy's "no kms:Decrypt" contract above stays literally true.
      toset([for statement in jsondecode(aws_iam_role_policy.manifest_producer_catalog_decrypt[0].policy).Statement : statement.Sid]) == toset([
        "DecryptOnlyProvisionedCellCatalog",
      ]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_catalog_decrypt[0].policy).Statement : statement.Sid => statement })["DecryptOnlyProvisionedCellCatalog"].Action == "kms:Decrypt" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_catalog_decrypt[0].policy).Statement : statement.Sid => statement })["DecryptOnlyProvisionedCellCatalog"].Resource == var.provisioned_cell_catalog_kms_key_arn &&
      # DynamoDB, never S3/Secrets Manager/ECR — the same CMK protects those
      # stores and ViaService is the only thing keeping this decrypt off them.
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_catalog_decrypt[0].policy).Statement : statement.Sid => statement })["DecryptOnlyProvisionedCellCatalog"].Condition.StringEquals["kms:ViaService"] == "dynamodb.us-east-2.amazonaws.com" &&
      keys(({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_catalog_decrypt[0].policy).Statement : statement.Sid => statement })["DecryptOnlyProvisionedCellCatalog"].Condition) == ["StringEquals"] &&
      # The catalog CMK is a distinct key from the attestation CMK.
      var.provisioned_cell_catalog_kms_key_arn != var.runtime_attestation_kms_key_arn
    )
    error_message = "The provisioned-cell catalog decrypt must be exact-key, DynamoDB-only, and separate from the core read policy."
  }

  assert {
    condition = (
      toset([for statement in jsondecode(aws_iam_role_policy.manifest_producer_terraform_state.policy).Statement : statement.Sid]) == toset([
        "ReadExactSandboxTerraformState",
        "DecryptOnlyExactSandboxTerraformState",
      ]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_terraform_state.policy).Statement : statement.Sid => statement })["ReadExactSandboxTerraformState"].Action == "s3:GetObject" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_terraform_state.policy).Statement : statement.Sid => statement })["ReadExactSandboxTerraformState"].Resource == "arn:aws:s3:::layerv-terraform-state-767397897469/nhp/sandbox/terraform.tfstate" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_terraform_state.policy).Statement : statement.Sid => statement })["DecryptOnlyExactSandboxTerraformState"].Resource == "arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_terraform_state.policy).Statement : statement.Sid => statement })["DecryptOnlyExactSandboxTerraformState"].Condition.StringEquals["kms:ViaService"] == "s3.us-east-2.amazonaws.com" &&
      ({ for statement in jsondecode(aws_iam_role_policy.manifest_producer_terraform_state.policy).Statement : statement.Sid => statement })["DecryptOnlyExactSandboxTerraformState"].Condition.StringEquals["kms:EncryptionContext:aws:s3:arn"] == "arn:aws:s3:::layerv-terraform-state-767397897469/nhp/sandbox/terraform.tfstate"
    )
    error_message = "Terraform state access must be one exact object and its exact S3-only KMS context."
  }

  assert {
    condition = (
      length(aws_iam_role_policy.manifest_producer_core.policy) +
      length(aws_iam_role_policy.manifest_producer_attestations[0].policy) +
      length(aws_iam_role_policy.manifest_producer_catalog_decrypt[0].policy) +
      length(aws_iam_role_policy.manifest_producer_terraform_state.policy)
    ) <= 10240
    error_message = "The manifest producer's aggregate inline-policy text must remain within IAM's 10,240-character role quota."
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
      strcontains(file("${path.module}/README.md"), "carries no Connector workflow lineage") &&
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
        "ReadBoundProofAccountCredential",
        "ReadBoundProofAccountCredentialDigest",
        "ConvergeExactProofCustomer",
        "ConvergeAndRemoveExactProofAccountKey",
        "DeleteRunBoundProofCredential",
        "CreateRunBoundProofCredential",
        "TagRunBoundProofCredential",
        "ReadExactAuthorityProofConcurrency",
        "ReadExactAuthorityProofAliases",
        "ReadAuthorityProofMetrics",
        "ReadAssignmentProofCheckpoint",
        "WriteAssignmentProofReceipt",
        "DenyAssignmentProofCheckpointWrites",
        "ReadTransportProofCheckpoint",
        "WriteTransportProofReceipt",
        "DenyTransportProofCheckpointWrites",
        "ReadExactLifecycleRouteLogs",
        "EncryptAssignmentProofHandshake",
        "ResolveAssignmentProofHandshakeKey",
        "ReadAndDeleteBoundRecoveryRequest",
        "PrepareExactUnlimitedProofOwner",
        "CreateBoundRecoveryResponse",
        "TagBoundRecoveryResponse",
      ]) &&
      !strcontains(aws_iam_role_policy.controller.policy, "ec2:") &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadAndDeleteBoundRecoveryRequest"].Resource == "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/udp-proof/recovery/request/*" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadAndDeleteBoundRecoveryRequest"].Action) == toset(["secretsmanager:GetSecretValue", "secretsmanager:DeleteSecret"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["PrepareExactUnlimitedProofOwner"].Resource == "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-customers" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["PrepareExactUnlimitedProofOwner"].Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == ["layerv-nhp-sandbox-udp-proof"] &&
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
      toset(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["PrepareOneTimeJITEncryption"].Action) == toset(["kms:Decrypt", "kms:GenerateDataKey"]) &&
      keys(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["PrepareOneTimeJITEncryption"].Condition) == ["StringEquals"] &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["PrepareOneTimeJITEncryption"].Condition.StringEquals["kms:ViaService"] == local.secrets_kms_via_service &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadBoundProofAccountCredential"].Resource == aws_secretsmanager_secret.proof_account_credential.arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadBoundProofAccountCredential"].Condition.StringEquals["secretsmanager:ResourceTag/Purpose"] == "udp-proof-account-credential" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadBoundProofAccountCredentialDigest"].Resource == local.proof_account_sha_parameter_arn &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ConvergeExactProofCustomer"].Action) == toset(["dynamodb:GetItem", "dynamodb:PutItem"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ConvergeExactProofCustomer"].Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == [local.proof_account_owner_id] &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ConvergeAndRemoveExactProofAccountKey"].Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == [var.proof_account_credential_sha256] &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateRunBoundProofCredential"].Resource == local.proof_account_jit_arn_pattern &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["CreateRunBoundProofCredential"].Condition.StringEquals["aws:RequestTag/Purpose"] == local.proof_account_jit_purpose &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["DeleteRunBoundProofCredential"].Resource == local.proof_account_jit_arn_pattern &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadExactAuthorityProofConcurrency"].Action) == toset(["lambda:GetFunctionConcurrency", "lambda:ListProvisionedConcurrencyConfigs"]) &&
      length(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadExactAuthorityProofConcurrency"].Resource) == 4 &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadExactAuthorityProofAliases"].Action == "lambda:GetAlias" &&
      length(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadExactAuthorityProofAliases"].Resource) == 8 &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadAuthorityProofMetrics"].Action == "cloudwatch:GetMetricStatistics" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadAuthorityProofMetrics"].Resource == "*" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadAuthorityProofMetrics"].Condition.StringEquals["aws:RequestedRegion"] == "us-east-2" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadAssignmentProofCheckpoint"].Action == "s3:GetObject" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadAssignmentProofCheckpoint"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/checkpoint.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["WriteAssignmentProofReceipt"].Action == "s3:PutObject" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["WriteAssignmentProofReceipt"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/receipt.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["DenyAssignmentProofCheckpointWrites"].Effect == "Deny" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["DenyAssignmentProofCheckpointWrites"].Action == "s3:PutObject" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["DenyAssignmentProofCheckpointWrites"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/checkpoint.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["EncryptAssignmentProofHandshake"].Resource == aws_kms_key.assignment_handshake.arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ResolveAssignmentProofHandshakeKey"].Action == "kms:DescribeKey" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ResolveAssignmentProofHandshakeKey"].Resource == aws_kms_key.assignment_handshake.arn &&
      output.assignment_handshake_kms_key_arn == aws_kms_key.assignment_handshake.arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadTransportProofCheckpoint"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/transport-checkpoint.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["WriteTransportProofReceipt"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/transport-receipt.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["DenyTransportProofCheckpointWrites"].Effect == "Deny" &&
      ({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadExactLifecycleRouteLogs"].Action == "logs:FilterLogEvents" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.controller.policy).Statement : statement.Sid => statement })["ReadExactLifecycleRouteLogs"].Resource) == toset([
        "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/cell0/qurl-api:*",
        "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/cell1/qurl-api:*",
        "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay:*",
      ])
    )
    error_message = "The workflow controller must retain no EC2 surface and may touch only exact tagged run metadata, the bound proof account, and its digest-fenced Control rows."
  }

  assert {
    condition = (
      length(aws_iam_policy.controller_control_data_decrypt) == 1 &&
      length(aws_iam_role_policy_attachment.controller_control_data_decrypt) == 1 &&
      aws_iam_role_policy_attachment.controller_control_data_decrypt[0].role == aws_iam_role.controller.name &&
      aws_iam_role_policy_attachment.controller_control_data_decrypt[0].policy_arn == aws_iam_policy.controller_control_data_decrypt[0].arn &&
      toset([for statement in jsondecode(aws_iam_policy.controller_control_data_decrypt[0].policy).Statement : statement.Sid]) == toset(["DecryptOnlyProofAccountTables"]) &&
      jsondecode(aws_iam_policy.controller_control_data_decrypt[0].policy).Statement[0].Action == "kms:Decrypt" &&
      jsondecode(aws_iam_policy.controller_control_data_decrypt[0].policy).Statement[0].Resource == var.provisioned_cell_catalog_kms_key_arn &&
      jsondecode(aws_iam_policy.controller_control_data_decrypt[0].policy).Statement[0].Condition.StringEquals["kms:ViaService"] == "dynamodb.us-east-2.amazonaws.com"
    )
    error_message = "The proof-account decrypt must be one exact-key, DynamoDB-only managed policy attached only to the controller role."
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
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundQURLGoAgentState"].Resource) == var.proof_kms_key_arns &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundQURLGoAgentState"].Action) == toset(["kms:Encrypt", "kms:Decrypt"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundQURLGoAgentState"].Condition.StringEquals == {
        "kms:EncryptionContext:qurl_purpose"          = "qurl-go/agent-state"
        "kms:EncryptionContext:qurl_envelope_version" = "1"
        "kms:EncryptionContext:qurl_provider_id"      = "aws-kms"
      } &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundQURLGoAgentState"].Condition.StringLike == {
        "kms:EncryptionContext:qurl_agent_id" = "qurl-go-sandbox-*"
      } &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundQURLGoAgentState"].Condition["ForAllValues:StringEquals"]["kms:EncryptionContextKeys"]) == toset(["qurl_purpose", "qurl_envelope_version", "qurl_provider_id", "qurl_agent_id"]) &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundConnectorAgentState"].Resource) == var.proof_kms_key_arns &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundConnectorAgentState"].Action) == toset(["kms:Encrypt", "kms:Decrypt"]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundConnectorAgentState"].Condition.StringEquals == {
        "kms:EncryptionContext:purpose"          = "qurl-go/agent-state-dek/qurl-go/agent-state"
        "kms:EncryptionContext:envelope_version" = "1"
        "kms:EncryptionContext:provider_id"      = "aws-kms"
      } &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundConnectorAgentState"].Condition.StringLike == {
        "kms:EncryptionContext:agent_id" = "connector-sandbox-*"
      } &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["UseBoundConnectorAgentState"].Condition["ForAllValues:StringEquals"]["kms:EncryptionContextKeys"]) == toset(["purpose", "envelope_version", "provider_id", "agent_id"]) &&
      !strcontains(aws_iam_role_policy.runner.policy, "qurl-agent-x25519-private-key") &&
      !strcontains(aws_iam_role_policy.runner.policy, "\"kms:EncryptionContext:provider\"") &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["ReadAndDeleteRunBoundProofCredential"].Resource == local.proof_account_jit_arn_pattern &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["ReadAndDeleteRunBoundProofCredential"].Condition.StringEquals["secretsmanager:ResourceTag/Purpose"] == local.proof_account_jit_purpose &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["ConsumeExactProofOTPMailboxQueue"].Resource == aws_sqs_queue.proof_otp_mailbox.arn &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["ConsumeExactProofOTPMailboxObjects"].Resource == "${aws_s3_bucket.proof_otp_mailbox.arn}/${local.proof_mailbox_object_prefix}*" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["WriteAssignmentProofCheckpoint"].Action == "s3:PutObject" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["WriteAssignmentProofCheckpoint"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/checkpoint.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["ReadAssignmentProofReceipt"].Action == "s3:GetObject" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["ReadAssignmentProofReceipt"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/receipt.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DenyAssignmentProofReceiptWrites"].Effect == "Deny" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DenyAssignmentProofReceiptWrites"].Action == "s3:PutObject" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DenyAssignmentProofReceiptWrites"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/receipt.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["WriteTransportProofCheckpoint"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/transport-checkpoint.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["ReadTransportProofReceipt"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-udp-proof-handshake-767397897469/handshake/v1/*/transport-receipt.json" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["DenyTransportProofReceiptWrites"].Effect == "Deny" &&
      ({ for statement in jsondecode(aws_iam_role_policy.runner.policy).Statement : statement.Sid => statement })["EncryptAssignmentProofHandshake"].Resource == aws_kms_key.assignment_handshake.arn
    )
    error_message = "Proof KMS access must be exact-key Describe/Encrypt/Decrypt and independently bound to qurl-go and Connector sealed-state contexts."
  }

  assert {
    condition = (
      aws_lambda_function.broker.reserved_concurrent_executions == 1 &&
      aws_lambda_function.broker.timeout == 30 &&
      aws_lambda_function.broker.logging_config[0].log_format == "Text" &&
      aws_lambda_function.broker.logging_config[0].log_group == aws_cloudwatch_log_group.broker.name &&
      aws_lambda_function.broker.environment[0].variables.EIP_ALLOCATION_ID == aws_eip.source.id &&
      aws_lambda_function.broker.environment[0].variables.JIT_SECRET_PREFIX == "layerv-nhp-sandbox/udp-proof/jit/" &&
      aws_lambda_function.broker.environment[0].variables.RECOVERY_REQUEST_SECRET_PREFIX == "layerv-nhp-sandbox/udp-proof/recovery/request/" &&
      aws_lambda_function.broker.environment[0].variables.RECOVERY_RESPONSE_SECRET_PREFIX == "layerv-nhp-sandbox/udp-proof/recovery/response/" &&
      toset(({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["InspectProofSecretMetadata"].Resource) == toset([
        local.jit_secret_arn_pattern,
        local.recovery_request_secret_arn_pattern,
        local.recovery_response_secret_arn_pattern,
      ]) &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["DeleteExpiredRecoveryRequests"].Resource == local.recovery_request_secret_arn_pattern &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["DeleteExpiredRecoveryRequests"].Condition.StringEquals["secretsmanager:ResourceTag/Purpose"] == "udp-proof-recovery-request" &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["DeleteExpiredRecoveryResponses"].Resource == local.recovery_response_secret_arn_pattern &&
      ({ for statement in jsondecode(aws_iam_role_policy.broker.policy).Statement : statement.Sid => statement })["DeleteExpiredRecoveryResponses"].Condition.StringEquals["secretsmanager:ResourceTag/Purpose"] == "udp-proof-recovery-response" &&
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

run "omit_attestation_access_until_storage_is_pinned" {
  command = plan

  variables {
    runtime_attestation_bucket_arn  = null
    runtime_attestation_kms_key_arn = null
  }

  assert {
    condition     = length(aws_iam_role_policy.manifest_producer_attestations) == 0
    error_message = "The manifest producer must receive no wildcard or placeholder attestation access before exact storage is provisioned."
  }
}

run "omit_catalog_decrypt_until_cmk_is_pinned" {
  command = plan

  variables {
    provisioned_cell_catalog_kms_key_arn = null
  }

  assert {
    condition = (
      length(aws_iam_role_policy.manifest_producer_catalog_decrypt) == 0 &&
      length(aws_iam_policy.controller_control_data_decrypt) == 0 &&
      length(aws_iam_role_policy_attachment.controller_control_data_decrypt) == 0
    )
    error_message = "No manifest or proof-account decrypt may exist before the exact Control data key is pinned."
  }
}

run "reject_cross_account_catalog_cmk" {
  command = plan

  variables {
    provisioned_cell_catalog_kms_key_arn = "arn:aws:kms:us-east-2:111122223333:key/55555555-aaaa-bbbb-cccc-666666666666"
  }

  expect_failures = [
    aws_iam_policy.controller_control_data_decrypt,
    aws_iam_role_policy.manifest_producer_catalog_decrypt,
  ]
}

run "reject_catalog_cmk_reused_from_attestation_storage" {
  command = plan

  variables {
    provisioned_cell_catalog_kms_key_arn = "arn:aws:kms:us-east-2:767397897469:key/33333333-aaaa-bbbb-cccc-444444444444"
  }

  expect_failures = [var.provisioned_cell_catalog_kms_key_arn]
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

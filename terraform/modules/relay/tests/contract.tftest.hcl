mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      id     = "us-east-2"
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

  mock_data "aws_prefix_list" {
    defaults = {
      id = "pl-0123456789abcdef0"
    }
  }
}

mock_provider "archive" {}
mock_provider "time" {}

override_resource {
  target          = aws_security_group.relay
  override_during = plan
  values          = { id = "sg-33333333333333333" }
}

override_resource {
  target          = aws_security_group.alb
  override_during = plan
  values          = { id = "sg-44444444444444444" }
}

override_resource {
  target          = aws_lb_target_group.relay
  override_during = plan
  values          = { arn = "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/relay-browser/0000000000000003" }
}

variables {
  environment                    = "sandbox"
  name_prefix                    = "layerv-nhp-sandbox"
  account_id                     = "767397897469"
  vpc_id                         = "vpc-0123456789abcdef0"
  network_ready_token            = "relay-network-ready"
  vpc_endpoint_security_group_id = "sg-0123456789abcdef0"
  server_security_group_id       = "sg-11111111111111111"
  public_subnet_ids              = ["subnet-public-a", "subnet-public-b", "subnet-public-c"]
  relay_subnet_ids               = ["subnet-relay-a", "subnet-relay-b", "subnet-relay-c"]
  nhp_server_cidr_blocks         = ["10.100.10.0/24", "10.100.11.0/24", "10.100.12.0/24"]
  asg_name                       = "layerv-nhp-sandbox-relay-dmz"
  relay_repo_url                 = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv-nhp-sandbox-relay"
  relay_repo_arn                 = "arn:aws:ecr:us-east-2:767397897469:repository/layerv-nhp-sandbox-relay"
  server_ami_id                  = "ami-0123456789abcdef0"
  ssm_image_tag_parameter        = "/sandbox/nhp/relay/image-tag"
  relay_secret_arn               = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox-relay-identity-abc123"
  ebs_kms_key_arn                = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000001"
  logs_kms_key_arn               = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000002"
  secrets_kms_key_arn            = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000003"
  certificate_arn                = "arn:aws:acm:us-east-2:767397897469:certificate/00000000-0000-0000-0000-000000000004"
  cell_servers = [{
    name       = "sandbox-cell0"
    public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    host       = "internal-server-nlb.elb.amazonaws.com"
    port       = 62206
  }]
}

run "browser_relay_contract" {
  command = plan

  assert {
    condition     = toset(aws_autoscaling_group.relay.target_group_arns) == toset([aws_lb_target_group.relay.arn])
    error_message = "The relay ASG must attach only to the browser HTTPS ALB target group; native SDKs use the assigned cell's public NLB."
  }

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.relay_http_from_alb.referenced_security_group_id == aws_security_group.alb.id &&
      aws_vpc_security_group_ingress_rule.relay_http_from_alb.ip_protocol == "tcp" &&
      aws_vpc_security_group_ingress_rule.relay_udp_ack_return.from_port == 62207 &&
      aws_vpc_security_group_ingress_rule.relay_udp_ack_return.to_port == 62207 &&
      aws_vpc_security_group_ingress_rule.relay_udp_ack_return.ip_protocol == "udp" &&
      aws_vpc_security_group_ingress_rule.relay_udp_ack_return.referenced_security_group_id == var.server_security_group_id
    )
    error_message = "Relay ingress must be browser HTTPS from the ALB plus private authenticated server returns on UDP 62207."
  }

  assert {
    condition = (
      strcontains(base64decode(aws_launch_template.relay.user_data), "udp_listen_addr = \"0.0.0.0:62207\"") &&
      !strcontains(base64decode(aws_launch_template.relay.user_data), "native_listen_addr") &&
      !strcontains(base64decode(aws_launch_template.relay.user_data), "native_server")
    )
    error_message = "Rendered relay bootstrap must configure only the private NHP_RLY return socket, not native SDK ingress."
  }
}

run "private_return_port_is_fixed" {
  command = plan

  variables {
    udp_listen_port = 62206
  }

  expect_failures = [var.udp_listen_port]
}

run "browser_relay_supports_multiple_cells" {
  command = plan

  variables {
    cell_servers = [
      {
        name       = "sandbox-cell0"
        public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        host       = "internal-server-0.elb.amazonaws.com"
        port       = 62206
      },
      {
        name       = "sandbox-cell1"
        public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        host       = "internal-server-1.elb.amazonaws.com"
        port       = 62206
      },
    ]
  }

  assert {
    condition = (
      strcontains(base64decode(aws_launch_template.relay.user_data), "name = \"sandbox-cell0\"") &&
      strcontains(base64decode(aws_launch_template.relay.user_data), "name = \"sandbox-cell1\"")
    )
    error_message = "Browser HTTPS routing must preserve every configured cell server."
  }
}

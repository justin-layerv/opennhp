mock_provider "aws" {
  mock_resource "aws_eip" {
    override_during = plan

    defaults = {
      id        = "eipalloc-0123456789abcdef0"
      public_ip = "198.51.100.42"
    }
  }
}
mock_provider "aws" {
  alias = "us_east_1"
}
mock_provider "archive" {}
mock_provider "time" {}

variables {
  environment        = "test"
  domain_name        = "nhp.example.com"
  hosted_zone        = "example.com"
  acme_email         = "test@example.com"
  vpc_id             = "vpc-00000000000000000"
  vpc_cidr           = "10.0.0.0/16"
  public_subnet_ids  = ["subnet-00000000000000000"]
  private_subnet_ids = ["subnet-00000000000000001"]
  ac_repo_url        = "000000000000.dkr.ecr.us-east-2.amazonaws.com/nhp-ac"
  ac_repo_arn        = "arn:aws:ecr:us-east-2:000000000000:repository/nhp-ac"
  namespace_id       = "ns-00000000000000000"
  namespace_name     = "nhp.test.internal"
  name_prefix        = "nhp-test"
  customer_id        = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
  license_key        = "test-license-key"
  license_key_hash   = "test-license-hash"
  license_key_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
  server_endpoint    = "server.nhp.test.internal"
  server_secret_arn  = "arn:aws:secretsmanager:us-east-2:000000000000:secret:nhp-server"
}

run "reject_enabled_gate_on_disabled_router" {
  command = plan

  variables {
    qurl_router_config = {
      enabled                      = false
      api_url                      = "https://api.example.com"
      base_domain                  = "qurl.example.com"
      require_connector_routing_id = true
    }
  }

  expect_failures = [var.qurl_router_config]
}

run "render_default_off_gate_in_ac_user_data" {
  command = plan

  variables {
    qurl_service_token_secret_arn = "arn:aws:secretsmanager:us-east-2:000000000000:secret:qurl-service-token"
    qurl_router_config = {
      enabled                      = true
      api_url                      = "https://api.example.com"
      base_domain                  = "qurl.example.com"
      require_connector_routing_id = false
    }
  }

  assert {
    condition     = length(terraform_data.ac_user_data_qurl_router_render_check) == 1
    error_message = "Expected one AC qurl-router render-check resource so its default-off preconditions run during plan."
  }
}

run "render_enabled_gate_in_ac_user_data" {
  command = plan

  variables {
    qurl_service_token_secret_arn = "arn:aws:secretsmanager:us-east-2:000000000000:secret:qurl-service-token"
    qurl_router_config = {
      enabled                      = true
      api_url                      = "https://api.example.com"
      base_domain                  = "qurl.example.com"
      require_connector_routing_id = true
    }
  }

  assert {
    condition     = length(terraform_data.ac_user_data_qurl_router_render_check) == 1
    error_message = "Expected one AC qurl-router render-check resource so its enabled-gate preconditions run during plan."
  }
}

run "source_fenced_registration_admits_complete_managed_eip_pool" {
  command = plan

  variables {
    enable_blue_green            = true
    enable_egress_eips           = true
    ac_max_capacity              = 3
    server_nlb_source_fenced     = true
    server_nlb_security_group_id = "sg-0123456789abcdef0"
  }

  assert {
    condition     = length(aws_eip.ac) == 7
    error_message = "Blue/green AC capacity 3 must retain six fleet EIPs plus one rolling-refresh slack EIP."
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.server_nlb_registration) == 7
    error_message = "Every managed AC EIP, including the rolling-refresh slack address, must receive one NLB registration rule."
  }

  assert {
    condition = alltrue([
      for rule in aws_vpc_security_group_ingress_rule.server_nlb_registration :
      rule.security_group_id == "sg-0123456789abcdef0" &&
      rule.ip_protocol == "udp" &&
      rule.from_port == 443 &&
      rule.to_port == 443 &&
      rule.cidr_ipv4 == "198.51.100.42/32"
    ])
    error_message = "Managed AC registration rules must be exact EIP /32 UDP 443 ingress on only the assigned public NLB SG."
  }
}

run "source_fenced_registration_requires_managed_eips" {
  command = plan

  variables {
    enable_egress_eips           = false
    server_nlb_source_fenced     = true
    server_nlb_security_group_id = "sg-0123456789abcdef0"
  }

  expect_failures = [aws_launch_template.ac]
}

run "source_fenced_registration_requires_nlb_security_group" {
  command = plan

  variables {
    enable_egress_eips       = true
    server_nlb_source_fenced = true
  }

  expect_failures = [aws_launch_template.ac]
}

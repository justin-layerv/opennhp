mock_provider "aws" {}
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

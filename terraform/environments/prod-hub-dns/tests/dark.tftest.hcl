mock_provider "aws" {}

mock_provider "aws" {
  alias = "route53_mgmt"
}

run "source_locked_root_is_inert" {
  command = plan

  assert {
    condition = (
      length(data.aws_lb.hub) == 0 &&
      length(aws_route53_record.hub) == 0
    )
    error_message = "The source-locked production Hub DNS root must neither look up an NLB nor create a Route 53 record."
  }
}

run "activation_requires_source_change" {
  command = plan

  variables {
    hub_dns_enabled = true
  }

  expect_failures = [var.hub_dns_enabled]
}

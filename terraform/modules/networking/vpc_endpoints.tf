# ==================== QURL Service VPC Endpoints ====================
#
# Additional VPC endpoints for the QURL ECS service AWS dependencies.
# Gated on `var.deploy_vpc_endpoints` so that we can roll them out
# environment-by-environment without paying the per-AZ hourly cost
# everywhere up front (gateway endpoints are free; SQS interface
# endpoints are ~$7.50/mo/AZ).
#
# Layout:
#
#   - DynamoDB gateway endpoint (free) lives in this file because it
#     uses route_table_ids (not subnet_ids + SG), which is a different
#     resource shape from the always-on interface endpoints.
#
#   - SQS interface endpoint is conditionally added to
#     `local.interface_endpoints` in main.tf so it inherits the shared
#     SG, subnet placement, private DNS, and tagging from the existing
#     for_each loop. Adding it as a separate resource here would
#     duplicate that wiring.
#
# Existing always-on endpoints (defined in main.tf):
#   S3 gateway, ECR (api + dkr), CloudWatch Logs, Secrets Manager,
#   SSM, ssmmessages, servicediscovery, guardduty-data.
#
# Why these endpoints, not others:
#   - DynamoDB: QURL service stores all domain/owner state in DynamoDB
#     and is the largest source of NAT-gateway data-processing cost.
#   - SQS: QURL publishes usage events to a FIFO queue consumed by the
#     billing usage reporter Lambda; same NAT cost concern.
#
# Why no KMS interface endpoint: SQS server-side encryption is handled
# by AWS internally — clients (qurl-api) call SQS directly and never
# touch KMS over the wire. Adding a KMS endpoint would not save NAT
# bytes for this traffic.
#
# Endpoint policies: both endpoints currently use the default open
# policy. See follow-up issue for tighter scoping to specific tables /
# queue ARNs (defence-in-depth, not a hard security gate).
#
# References: https://github.com/layervai/nhp/issues/220
#
# The `deploy_vpc_endpoints` input variable is declared in variables.tf
# alongside the other module inputs.

# DynamoDB Gateway Endpoint (free) - primary datastore for QURL service.
# Uses count rather than for_each because gateway endpoints are not
# interchangeable with interface endpoints (different resource shape).
resource "aws_vpc_endpoint" "dynamodb" {
  count = var.deploy_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.id}.dynamodb"
  vpc_endpoint_type = "Gateway"

  # Attach to every route table in the VPC. Gateway endpoints work by
  # injecting a managed prefix-list route into each table, so we want
  # public, private, and isolated subnets to all bypass NAT for
  # DynamoDB traffic. The public route table is intentionally included:
  # ECS service tasks may run in public subnets in some environments
  # (e.g. dev) and the gateway endpoint is harmless when unused.
  route_table_ids = concat(
    [aws_route_table.public.id],
    aws_route_table.private[*].id,
    [aws_route_table.isolated.id]
  )

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpce-dynamodb"
    Component = "networking"
  })
}

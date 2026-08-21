# Input variables for the sandbox cell1 (lean NHP-server) root.
# Values live in terraform.tfvars.

variable "environment" {
  description = <<-EOT
    Infrastructure namespace for this cell. It MUST remain distinct from
    cell0's "sandbox" so resource names and /sandbox-cell1/... SSM paths do not
    collide. It is deliberately not the NHP/Authority protocol environment;
    protocol_environment below supplies that separate identity.
  EOT
  type        = string
  default     = "sandbox-cell1"

  validation {
    condition     = var.environment != "sandbox" && var.environment != "prod"
    error_message = "environment must be distinct from cell0 (\"sandbox\") and prod to avoid name/SSM collisions."
  }
}

variable "protocol_environment" {
  description = "Logical NHP/Authority environment. Both sandbox cells use sandbox; cell identity is carried independently as cell1."
  type        = string
  default     = "sandbox"

  validation {
    condition     = var.protocol_environment == "sandbox"
    error_message = "sandbox cell1 must use logical protocol environment sandbox."
  }
}

variable "cell_id" {
  description = "Cell identifier. cell1 is the second cell of the two-cell UDP substrate."
  type        = string
  default     = "cell1"
}

variable "connector_authority_cell_config" {
  description = "Optional exact cell1 Connector Authority caller graph. Dark by default; activate only after the Control runtime, cell1 protocol environment, and replacement CIDR are applied and verified."
  type = object({
    environment                            = string
    aws_account_id                         = string
    aws_region                             = string
    issue_registration_otp_alias_arn       = string
    activate_registration_alias_arn        = string
    complete_registration_alias_arn        = string
    complete_credential_recovery_alias_arn = string
    resolve_connector_resource_alias_arn   = optional(string)
    authority_lambda_timeout               = string
    handler_budget                         = string
    packet_budget                          = string
    response_reserve                       = string
    write_budget                           = string
  })
  default = null
}

variable "aws_region" {
  description = "AWS region. Same region as cell0 (us-east-2); the cells are peered only logically, via the control plane."
  type        = string
  default     = "us-east-2"
}

variable "aws_account_id" {
  description = "AWS account ID (sandbox account, shared with cell0)."
  type        = string
  default     = "767397897469"
}

variable "vpc_cidr" {
  description = <<-EOT
    cell1 VPC CIDR. MUST NOT overlap cell0's 10.100.0.0/16, cell0's relay
    DMZ 10.101.0.0/16, the Control VPC's 10.102.0.0/16, the UDP proof
    runner's 10.103.0.0/28, or prod's 10.200.0.0/16. The 2026-07-25
    all-enabled-region routing audit selected 10.104.0.0/16.
  EOT
  type        = string
  default     = "10.104.0.0/16"

  validation {
    # Rollback intentionally changes this literal, the default above, and the
    # root tfvars together; see docs/runbooks/sandbox-cell1-vpc-cidr-relocation.md.
    condition     = var.vpc_cidr == "10.104.0.0/16"
    error_message = "The reviewed sandbox cell1 VPC CIDR is 10.104.0.0/16; change it only with a new all-region routing audit."
  }
}

variable "public_nhp_udp_ingress_cidrs" {
  description = <<-EOT
    Sources allowed at the cell1 public UDP NLB. A non-null list creates the NLB
    with its security group attached. Sandbox is open to developers inside and
    outside the company (qurl-go ADR 0001), so this is the open-edge value,
    matching the open Hub and cell0: the reassignment fixture moves agents from
    cell0 to cell1, so a fenced cell1 would strand them mid-lifecycle.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition     = length(var.public_nhp_udp_ingress_cidrs) == 1 && var.public_nhp_udp_ingress_cidrs[0] == "0.0.0.0/0"
    error_message = "Sandbox cell1 UDP ingress is open by decision (qurl-go ADR 0001) and must remain exactly [\"0.0.0.0/0\"]; changing sandbox access requires superseding that ADR."
  }
}

variable "domain_name" {
  description = <<-EOT
    NHP server hostname baked into the server identity/config (keygen Lambda
    Hostname). Sandbox domain is nhp.layerv.xyz (NOT .ai — that is prod). The
    PUBLIC per-cell DNS record for reaching this NLB is cell1.nhp.layerv.xyz,
    created by module.dns (see var.cell_dns_name); it is intentionally distinct
    from this value.
  EOT
  type        = string
  default     = "nhp.layerv.xyz"
}

variable "cell_dns_name" {
  description = "Per-cell public A-alias record pointing at cell1's NLB. Distinct from cell0 and from the bare nhp.layerv.xyz apex."
  type        = string
  default     = "cell1.nhp.layerv.xyz"
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for layerv.xyz (same account as cell0). Used to publish cell1.nhp.layerv.xyz."
  type        = string
  default     = "Z10394893FM38A1RXLL32"
}

variable "server_ami_id" {
  description = <<-EOT
    NHP server AMI. Leave null and modules/compute reads
    /sandbox-cell1/nhp/server/ami-id (this cell's own path). That SSM
    parameter must be seeded before the first plan/apply (packer/CI publishes
    it for cell0's /sandbox path; the cell1 path needs the same treatment).
    Set explicitly here to pin a specific AMI instead.
  EOT
  type        = string
  default     = null
}

variable "min_capacity" {
  description = "Blue ASG minimum. 1 is sufficient for the two-cell UDP proof; raise for resilience."
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Blue ASG maximum."
  type        = number
  default     = 2
}

variable "green_standby_min_size" {
  description = "Green (blue/green) ASG warm-standby size. 0 = cold standby, cheapest, still publishes the green target groups + SSM ARNs used for traffic switching."
  type        = number
  default     = 0
}

variable "log_level" {
  description = "NHP server log level (0=silent .. 5=trace). 4=debug matches the cell0 sandbox posture."
  type        = number
  default     = 4
}

variable "deploy_qurl_service" {
  description = "Create the private cell1 qurl-service data plane after its governed immutable runtime contract is published. Default false keeps the cell dark and creates no ECS/table/secret runtime."
  type        = bool
  default     = false
}

variable "qurl_auth0_domain" {
  description = "Auth0 issuer used by the cell-local qurl-service."
  type        = string
  default     = "auth.layerv.ai"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.qurl_auth0_domain))
    error_message = "qurl_auth0_domain must be a bare lowercase DNS hostname."
  }
}

variable "qurl_cookie_domain" {
  description = "Sandbox qURL cookie domain retained for application config even though cell1 has no public API ingress."
  type        = string
  default     = ".qurl.site.layerv.xyz"
}

variable "qurl_link_domain" {
  description = "Sandbox qURL access-link domain."
  type        = string
  default     = "qurl.link.layerv.xyz"
}

variable "qurl_site_domain" {
  description = "Sandbox qURL protected-resource domain and NHP redirect suffix."
  type        = string
  default     = "qurl.site.layerv.xyz"
}

variable "tags" {
  description = "Base tags applied to all cell1 resources."
  type        = map(string)
  default = {
    Organization = "LayerV"
    CostCenter   = "infrastructure"
    Owner        = "platform-team"
  }
}

variable "qurl_v2_issuer_key_alias" {
  description = <<-EOT
    Alias of the account-global qURL v2 issuer KMS key, owned by the cell0 root.
    cell1 reads it so both cells verify links against the SAME issuer identity.
    Never point this at a cell-local key: a second issuer would mean a link
    minted by one cell fails to verify at the other.
  EOT
  type        = string
  default     = "alias/layerv-nhp-sandbox-qurl-v2-issuer"
}

variable "qurl_v2_issuer_kid" {
  description = <<-EOT
    Key id under which the issuer public key is published in this cell's trust
    store. Must match the cell0 root's qurl_v2_issuer_kid; a mismatch means a
    link names an issuer this cell cannot look up.
  EOT
  type        = string
  default     = "qurl-issuer-sandbox-2026-07"
}

# Control identity plane for the NHP server's agent-keys read.
#
# Identity is global, not cell-scoped: the Connector Authority registers agent
# pubkeys for EVERY cell into the Control namespace, and the Hub can place a
# registered agent on this cell. A cell1 server still reading the cell-local
# qurl-agent-keys table therefore rejects every registered agent's knock with
# event="agent_unknown_pubkey" — the registrations only ever land in Control.
# These mirror the cell0 root's control_identity_* variables (terraform/
# variables.tf); this lean root only threads the agent-keys read path, because
# its private qurl-service is deliberately the cell-local data plane and holds
# no Control identity access (see qurl_service.tf).
#
# Empty keeps the server on this cell's own agent-keys table, which is the
# historical behavior. Setting it REQUIRES the Control table to be the live
# registration namespace; flipping first would point the server at rows that
# do not exist.
variable "control_identity_environment_id" {
  description = "Control namespace environment id for the agent-keys read (e.g. \"sandbox\"). Empty keeps the cell-local agent-keys table."
  type        = string
  default     = ""
}

variable "control_identity_home_region" {
  description = "Home region of the Control identity tables. Required when control_identity_environment_id is set; must equal this cell's region because the server's storage.toml renders a single DynamoDB region."
  type        = string
  default     = ""
}

variable "control_identity_kms_key_arn" {
  description = "KMS key encrypting the Control identity tables. Required when control_identity_environment_id is set — reads of the SSE-KMS Control agent-keys table fail with AccessDeniedException without decrypt on THIS key."
  type        = string
  default     = ""
}

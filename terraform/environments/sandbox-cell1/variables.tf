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
    DMZ 10.101.0.0/16, or prod's 10.200.0.0/16. 10.102.0.0/16 is the next
    free /16 in the sandbox account's cell range.
  EOT
  type        = string
  default     = "10.102.0.0/16"
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

variable "tags" {
  description = "Base tags applied to all cell1 resources."
  type        = map(string)
  default = {
    Organization = "LayerV"
    CostCenter   = "infrastructure"
    Owner        = "platform-team"
  }
}

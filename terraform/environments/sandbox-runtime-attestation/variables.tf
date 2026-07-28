variable "environment" {
  description = "Environment label. The runtime-attestation store is intentionally sandbox-only."
  type        = string
  default     = "sandbox"
}

variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "us-east-2"
}

variable "bucket_name" {
  description = "Exact runtime-attestation bucket name (part of the producer's accepted contract)."
  type        = string
  default     = "layerv-nhp-sandbox-runtime-attestations"
}

variable "attested_node_roles" {
  description = "Exact EC2 node role names that publish runtime attestations, keyed by the producer's workload key."
  type        = map(string)
  default = {
    nhp_cell0                  = "layerv-nhp-sandbox-server"
    nhp_cell1                  = "layerv-nhp-sandbox-cell1-server"
    qurl_reverse_tunnel_server = "layerv-nhp-sandbox-frps"
  }
}

variable "asg_name_ssm_parameters" {
  description = "Canonical SSM parameters holding each attested fleet's exact ASG names. Blue/green fleets list every colour."
  type        = map(list(string))
  default = {
    nhp_cell0 = [
      "/sandbox/nhp/server/blue-asg-name",
      "/sandbox/nhp/server/green-asg-name",
    ]
    nhp_cell1 = [
      "/sandbox-cell1/nhp/server/blue-asg-name",
      "/sandbox-cell1/nhp/server/green-asg-name",
    ]
    qurl_reverse_tunnel_server = [
      "/sandbox/nhp/reverse-tunnel-server/asg-name",
    ]
  }
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}

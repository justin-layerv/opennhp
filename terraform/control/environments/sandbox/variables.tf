variable "environment" {
  type    = string
  default = "sandbox"

  validation {
    condition     = var.environment == "sandbox"
    error_message = "This root is permanently bound to sandbox."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-2"

  validation {
    condition     = var.aws_region == "us-east-2"
    error_message = "The sandbox Connector Authority home region is us-east-2."
  }
}

variable "aws_account_id" {
  type    = string
  default = "767397897469"

  validation {
    condition     = var.aws_account_id == "767397897469"
    error_message = "This root is permanently bound to the sandbox AWS account."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.102.0.0/16"

  validation {
    condition     = var.vpc_cidr == "10.102.0.0/16"
    error_message = "The reviewed sandbox Control VPC CIDR is 10.102.0.0/16; change it only with a live overlap audit."
  }
}

variable "otp_email_from" {
  type    = string
  default = "noreply@notify.layerv.xyz"
}

variable "ses_configuration_set_name" {
  type    = string
  default = "layerv-nhp-sandbox-agent-otp"
}

variable "authority_runtime_contract" {
  description = "Nullable closed Connector Authority runtime contract. The permanent workflow supplies the only supported non-null value through its exact-main byte-verifying generator."
  type        = any
  default     = null
}

variable "authority_runtime_contract_evidence_verified" {
  description = "Internal exact-main generator latch. The generated ephemeral tfvars file sets this with the complete verified sandbox contract; committed inputs must leave it false."
  type        = bool
  default     = false
}

variable "authority_runtime_functions_enabled" {
  description = "Second, independent runtime-slice gate. Committed inputs leave it false so contract binding (Step 3) stays a foundation_contract-only transition; the Step-4 runtime apply supplies it true (via -var or the generated tfvars) on top of a bound contract. See the module variable of the same name."
  type        = bool
  default     = false
}

variable "hub_edge_enabled" {
  description = "Dark-first Step-5 gate for the Connector Hub public UDP edge (the three public edge subnets, the internet gateway and public route table + 0.0.0.0/0 route, and the public UDP-62206 Hub NLB, listener, and target group). Committed inputs leave it false; the Step-5 edge apply supplies it true (via -var or the generated tfvars). See the module variable of the same name."
  type        = bool
  default     = false
}

variable "hub_worker_enabled" {
  description = "Dark-first Step-5 gate for the Connector Hub Fargate worker (slice 5b): the ECS cluster/service/task-definition, the Hub key-material secret + keygen, the worker security group, and the ECR/S3 image-pull endpoints; it also opens the Lambda interface endpoint to the worker's task role. Requires hub_edge_enabled and a live authority runtime. Committed inputs leave it false; the Step-5 worker apply supplies it true (via -var or the generated tfvars). See the module variable of the same name."
  type        = bool
  default     = false
}

variable "tags" {
  type = map(string)
  default = {
    CostCenter   = "infrastructure"
    Organization = "LayerV"
    Owner        = "platform-team"
  }
}

terraform {
  # Pessimistic constraint keeps shared-state operations on reviewed 1.14.x.
  required_version = "~> 1.14"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
  }
}

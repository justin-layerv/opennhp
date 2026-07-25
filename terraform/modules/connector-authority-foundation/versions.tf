terraform {
  # Pessimistic constraint keeps shared-state operations on reviewed 1.14.x.
  required_version = "~> 1.14"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
    # The Hub keygen Lambda (slice 5b) packages its handler via data.archive_file.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}

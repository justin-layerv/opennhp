# Sandbox UDP proof runner (Step 8). Every value here is also the variable
# default; pinned explicitly so the runner's identity is legible in one place.

environment = "sandbox"
aws_region  = "us-east-2"

# Dedicated, unpeered /28 (free; matches the module's contract test).
runner_vpc_cidr   = "10.103.0.0/28"
availability_zone = "us-east-2a"

# GitHub Actions runner v2.336.0 linux-x64; SHA verified by download+hash.
runner_archive_url    = "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz"
runner_archive_sha256 = "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d"

# ⚠️ REQUIRED — set the confirmed agent-x25519-private-key SEALING CMK here before
# apply (get it from the qurl-connector owners). It is NOT authority-data: a live
# KMS grant check showed authority-data is the DDB/ECR data-plane key with no
# qurl-agent-x25519-private-key encryption context. Leaving this unset makes
# `terraform plan/apply` fail loudly (required variable), which is intended — the
# runner must not be applied with a guessed sealing key.
# proof_kms_key_arns = ["arn:aws:kms:us-east-2:767397897469:key/<confirmed-uuid>"]

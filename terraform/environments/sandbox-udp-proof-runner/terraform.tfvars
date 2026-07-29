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

# The runner uses the dedicated proof sealing CMK this root creates
# (proof_seal_kms.tf, alias/layerv-nhp-sandbox-udp-proof-agent-seal).
# Connector's LAYERV_AWS_KMS_KEY_ID and qurl-go's attended sealed-state proof use
# that alias under separate exact encryption contexts.

# Connector Authority data CMK (alias/layerv-nhp-sandbox-authority-data), created
# by the Control root. It encrypts layerv-nhp-sandbox-control-connector-authority,
# so the manifest producer needs a DynamoDB-scoped kms:Decrypt on it to read the
# provisioned-cell catalog rows at all. Confirmed with
#   aws dynamodb describe-table --table-name layerv-nhp-sandbox-control-connector-authority
#     --query 'Table.SSEDescription.KMSMasterKeyArn'
provisioned_cell_catalog_kms_key_arn = "arn:aws:kms:us-east-2:767397897469:key/83680792-1ed7-4825-beb2-2e67f8056aee"

# Runtime-attestation store (terraform/environments/sandbox-runtime-attestation).
# Both MUST be set together: manifest_producer.tf gates the entire attestation
# read policy on `runtime_attestation_bucket_arn == null ? 0 : 1`, so leaving
# these null silently produces a producer role with NO s3:GetBucketVersioning /
# ListBucketVersions / GetObjectVersion on the store. The producer then fails at
# "attestation versioning read failed" with AccessDenied — which is a missing
# grant, not a missing bucket.
# Values are that root's live outputs; the CMK is independently corroborated by
#   aws s3api get-bucket-encryption --bucket layerv-nhp-sandbox-runtime-attestations
#     --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID'
runtime_attestation_bucket_arn  = "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestations"
runtime_attestation_kms_key_arn = "arn:aws:kms:us-east-2:767397897469:key/aa7ea8c3-e938-48c2-a449-200328d31db3"

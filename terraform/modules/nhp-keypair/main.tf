# NHP Keypair Module
# Generates and stores NHP registration keypair in SSM Parameter Store
#
# This module creates a shared Curve25519 keypair for AC registration.
# All servers share this keypair so ACs can connect via NLB to any server.
#
# Per-server forwarding keypairs are generated at runtime by each server
# and stored in SSM Parameter Store at /nhp/server/{id}/private-key.
#
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.5 for full design.

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ==================== Locals ====================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id
}

# ==================== Lambda for Key Generation ====================
# Generates Curve25519 keypair and stores in SSM Parameter Store

resource "aws_iam_role" "keygen_lambda" {
  name = "${var.name_prefix}-registration-keygen"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-registration-keygen-role"
    Component = "nhp-keypair"
    Cell      = var.cell_id
  })
}

resource "aws_iam_role_policy_attachment" "keygen_lambda_basic" {
  role       = aws_iam_role.keygen_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "keygen_lambda_ssm" {
  name = "ssm-access"
  role = aws_iam_role.keygen_lambda.id

  # Use concat to conditionally include KMS statement (empty resource arrays are invalid)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Resource = "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/pool/*"
      }
      ], var.kms_key_arn != null ? [{
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
    }] : [])
  })
}

data "archive_file" "keygen_lambda" {
  type        = "zip"
  output_path = "${path.module}/keygen_lambda.zip"

  source {
    # Lambda code matches compute module pattern for X25519 key generation
    # See modules/compute/main.tf for the original implementation
    content  = <<-EOF
const { SSMClient, GetParameterCommand, PutParameterCommand } = require('@aws-sdk/client-ssm');
const crypto = require('crypto');

exports.handler = async (event) => {
  console.log('Registration keypair generation event:', JSON.stringify(event));

  const { ParameterName, ForceRegenerate } = event.ResourceProperties || event;
  const client = new SSMClient();

  // Check if key already exists (unless forced regeneration)
  if (!ForceRegenerate) {
    try {
      const existing = await client.send(new GetParameterCommand({
        Name: ParameterName,
        WithDecryption: true
      }));

      if (existing.Parameter && existing.Parameter.Value) {
        const parsed = JSON.parse(existing.Parameter.Value);
        if (parsed.privateKey && parsed.publicKey) {
          console.log('Valid keypair already exists, not regenerating');
          return {
            PhysicalResourceId: event.PhysicalResourceId || ParameterName,
            Data: { PublicKey: parsed.publicKey }
          };
        }
      }
    } catch (err) {
      // Log error context before re-throwing
      if (err.name !== 'ParameterNotFound') {
        console.error('Failed to check existing parameter:', JSON.stringify({
          error: err.name,
          message: err.message,
          parameterName: ParameterName
        }));
        throw err;
      }
      console.log('Parameter not found, generating new keypair');
    }
  }

  // Generate X25519 key pair using Node.js crypto
  // Pattern matches modules/compute/main.tf for consistency
  const keyPair = crypto.generateKeyPairSync('x25519');

  // Export keys in raw format and base64 encode
  const privateKeyRaw = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });
  const publicKeyRaw = keyPair.publicKey.export({ type: 'spki', format: 'der' });

  // Validate DER format before extraction (guard against Node.js crypto format changes)
  // PKCS8 X25519 private key: 48 bytes, last 32 are the key
  // SPKI X25519 public key: 44 bytes, last 32 are the key
  if (privateKeyRaw.length !== 48) {
    throw new Error('Expected PKCS8 X25519 private key to be 48 bytes, got ' + privateKeyRaw.length);
  }
  if (publicKeyRaw.length !== 44) {
    throw new Error('Expected SPKI X25519 public key to be 44 bytes, got ' + publicKeyRaw.length);
  }

  // Extract the 32-byte raw keys from DER format
  const privateKey = privateKeyRaw.slice(-32);
  const publicKey = publicKeyRaw.slice(-32);

  const privateKeyBase64 = privateKey.toString('base64');
  const publicKeyBase64 = publicKey.toString('base64');

  const keypair = {
    privateKey: privateKeyBase64,
    publicKey: publicKeyBase64,
    generatedAt: new Date().toISOString()
  };

  // Store in SSM Parameter Store as SecureString
  try {
    await client.send(new PutParameterCommand({
      Name: ParameterName,
      Value: JSON.stringify(keypair),
      Type: 'SecureString',
      Overwrite: true,
      Description: 'NHP shared registration keypair for AC initial connection'
    }));
  } catch (err) {
    console.error('Failed to store keypair in SSM:', JSON.stringify({
      error: err.name,
      message: err.message,
      parameterName: ParameterName
    }));
    throw err;
  }

  console.log('Generated and stored new registration keypair');

  return {
    PhysicalResourceId: event.PhysicalResourceId || ParameterName,
    Data: { PublicKey: keypair.publicKey }
  };
};
EOF
    filename = "index.js"
  }
}

resource "aws_lambda_function" "keygen" {
  function_name = "${var.name_prefix}-registration-keygen"
  role          = aws_iam_role.keygen_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  timeout       = 30

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-registration-keygen"
    Component = "nhp-keypair"
    Cell      = var.cell_id
  })
}

# Invoke Lambda to generate keypair
# Note: ignore_changes prevents re-invoking on every apply. The Lambda itself
# checks if a valid keypair exists before generating. To force key rotation,
# either delete the SSM parameter manually or use `terraform taint` on this resource.
# This pattern matches modules/compute/main.tf Lambda invocation.
resource "aws_lambda_invocation" "keygen" {
  function_name = aws_lambda_function.keygen.function_name

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      ParameterName   = "/nhp/pool/registration-key"
      ForceRegenerate = false
    }
  })

  depends_on = [aws_iam_role_policy.keygen_lambda_ssm]

  lifecycle {
    ignore_changes = [input]
  }
}

# ==================== SSM Parameter for Public Key ====================
# Store the public key separately for easy access by ACs
# (ACs need the public key in their config; servers need the private key)

resource "aws_ssm_parameter" "registration_public_key" {
  name        = "/nhp/pool/registration-public-key"
  description = "NHP registration public key (for AC config)"
  type        = "String"
  value       = jsondecode(aws_lambda_invocation.keygen.result).Data.PublicKey

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-registration-public-key"
    Component = "nhp-keypair"
    Cell      = var.cell_id
    Purpose   = "AC configuration"
  })
}

# ==================== IAM Policy for Server Access ====================
# Servers need to read the registration private key

resource "aws_iam_policy" "server_keypair_access" {
  name        = "${var.name_prefix}-keypair-read"
  description = "Read access to NHP registration keypair for servers"

  # Use concat to conditionally include KMS statement (empty resource arrays are invalid)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "SSMReadRegistrationKey"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/pool/registration-key"
        ]
      },
      {
        Sid    = "SSMManageServerKey"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/server/*"
        ]
      }
      ], var.kms_key_arn != null ? [{
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [var.kms_key_arn]
    }] : [])
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-keypair-read"
    Component = "nhp-keypair"
    Cell      = var.cell_id
  })
}

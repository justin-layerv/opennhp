# Packer template for NHP AC AMI
# Builds an AMI with AC binaries and Traefik plugins pre-installed
#
# Usage:
#   packer init nhp-ac.pkr.hcl
#   packer build -var 'runtime_packages_only=true' -var 'environment=sandbox' nhp-ac.pkr.hcl
#
# After building for Terraform-managed AC, the AMI ID is automatically
# published to SSM parameter:
#   /{environment}/nhp/ac/ami-id
#
# Terraform-managed AC instances still pull the deploy-selected Docker image at
# boot. This bake is load-bearing for OS/runtime packages only: user_data fails
# closed if jq/docker/ipset/etc. are missing and never falls back to apt.
#
# To build a full self-service/Marketplace image with embedded binaries:
#   packer build -var 'image_tag=abc123' -var 'plugin_bucket=layerv-nhp-sandbox-plugins' nhp-ac.pkr.hcl
#
# For AWS Marketplace submission:
#   packer build -var 'marketplace=true' -var 'product_version=1.0.0' ...
#
# This AMI is designed for:
# - AWS Marketplace distribution
# - Customer self-service deployment via user_data
# - Air-gapped/offline environments

packer {
  required_plugins {
    amazon = {
      version = "~> 1.3"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

# ==================== Variables ====================

variable "aws_region" {
  type        = string
  default     = "us-east-2"
  description = "AWS region for AMI"
}

variable "environment" {
  type        = string
  default     = "sandbox"
  description = "Environment name (sandbox, prod, marketplace)"
}

variable "image_tag" {
  type        = string
  default     = ""
  description = "Docker image tag to extract binaries from"
}

variable "ecr_repo" {
  type        = string
  default     = ""
  description = "ECR repository URL (defaults to layerv-nhp-{env}-ac)"
}

variable "plugin_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket containing plugins"
}

variable "traefik_plugins" {
  type        = list(string)
  default     = ["nhp-token-validator"]
  description = "List of Traefik plugins to include"
}

variable "plugin_version" {
  type        = string
  default     = "latest"
  description = "Plugin version to download"
}

variable "instance_type" {
  type        = string
  default     = "t3.medium"
  description = "Instance type for building"
}

variable "ami_name_prefix" {
  type        = string
  default     = "layerv-nhp-ac"
  description = "Prefix for AMI name"
}

variable "ami_description" {
  type        = string
  default     = "LayerV NHP Access Controller - Zero Trust Network Access"
  description = "AMI description"
}

variable "git_sha" {
  type        = string
  default     = "unknown"
  description = <<-EOT
    Git commit SHA at the time of the build. Used to tag the AMI and embed
    in the AMI name so an operator can grep an AMI back to the exact
    packer/* template version that produced it. CI passes this from
    $${{ github.sha }}. Local builds default to "unknown".
  EOT
}

variable "runtime_packages_only" {
  type        = bool
  default     = false
  description = "Build only the OS/runtime package layer used by Terraform-managed AC. Skips embedding AC binaries/plugins, which live user_data refreshes from ECR/S3 at boot."
}

variable "publish_ssm" {
  type        = bool
  default     = true
  description = "Publish the built AC AMI ID to /{environment}/nhp/ac/ami-id from the Packer shell-local post-processor. CI can disable this and publish from the workflow after switching to the environment deploy role."
}

# Marketplace-specific variables
variable "marketplace" {
  type        = bool
  default     = false
  description = "Build for AWS Marketplace submission"
}

variable "product_version" {
  type        = string
  default     = "1.0.0"
  description = "Product version for Marketplace"
}

variable "ami_regions" {
  type        = list(string)
  default     = []
  description = "Additional regions to copy AMI to (for Marketplace)"
}

# ==================== Locals ====================

locals {
  timestamp     = formatdate("YYYYMMDD-hhmmss", timestamp())
  git_sha_label = var.git_sha != "" ? var.git_sha : "unknown"
  git_sha_short = length(local.git_sha_label) >= 7 ? substr(local.git_sha_label, 0, 7) : local.git_sha_label
  ami_name      = var.marketplace ? "${var.ami_name_prefix}-${var.product_version}" : "${var.ami_name_prefix}-${var.environment}-${local.timestamp}-${local.git_sha_short}"

  # Common tags
  base_tags = {
    Name        = local.ami_name
    Environment = var.environment
    Component   = "nhp-ac"
    ManagedBy   = "packer"
  }

  # Marketplace-specific tags
  marketplace_tags = var.marketplace ? {
    ProductVersion = var.product_version
    Marketplace    = "true"
  } : {}

  # Build-time tags (not for final AMI)
  build_tags = {
    ImageTag            = var.image_tag
    BuildTime           = local.timestamp
    GitSHA              = var.git_sha
    RuntimePackagesOnly = var.runtime_packages_only ? "true" : "false"
  }

  all_tags = merge(local.base_tags, local.marketplace_tags, local.build_tags)
}

# ==================== Source ====================

source "amazon-ebs" "nhp-ac" {
  ami_name        = local.ami_name
  ami_description = var.ami_description
  instance_type   = var.instance_type
  region          = var.aws_region

  # Copy to additional regions for Marketplace
  ami_regions = var.ami_regions

  # Use latest Ubuntu 24.04 LTS (Marketplace-approved)
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"] # Canonical
    most_recent = true
  }

  ssh_username = "ubuntu"

  # Tags for the AMI
  tags = local.all_tags

  # Tags for the build instance
  run_tags = {
    Name = "packer-nhp-ac-build"
  }

  # EBS settings - Marketplace requires encrypted or specific volume types
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 30 # Minimum reasonable size
    volume_type           = "gp3"
    delete_on_termination = true
    # Encrypt every internal and Marketplace build so snapshots created from
    # the AMI inherit encryption at rest.
    encrypted = true
  }

  # Marketplace requires specific snapshot settings
  snapshot_tags = local.all_tags
}

# ==================== Build ====================

build {
  sources = ["source.amazon-ebs.nhp-ac"]

  # Install base dependencies
  provisioner "shell" {
    inline_shebang = "/bin/bash"
    inline = [
      "set -euo pipefail",
      "echo 'Installing base dependencies...'",
      "retry_with_backoff() {",
      "  local max_attempts=$1 delay=$2 max_delay=$3",
      "  shift 3",
      "  local attempt=1",
      "  while true; do",
      "    if \"$@\"; then",
      "      return 0",
      "    fi",
      "    if [ \"$attempt\" -ge \"$max_attempts\" ]; then",
      "      echo \"ERROR: $* failed after $max_attempts attempts\"",
      "      return 1",
      "    fi",
      "    echo \"$* failed (attempt $attempt/$max_attempts), retrying in $delay seconds...\"",
      "    sleep \"$delay\"",
      "    attempt=$((attempt + 1))",
      "    delay=$((delay * 2))",
      "    if [ \"$delay\" -gt \"$max_delay\" ]; then",
      "      delay=$max_delay",
      "    fi",
      "  done",
      "}",
      "apt_get_with_retry() {",
      "  retry_with_backoff 10 2 60 sudo env DEBIAN_FRONTEND=noninteractive apt-get \"$@\"",
      "}",
      "apt_get_with_retry update",
      # Pre-seed iptables-persistent so its install is non-interactive (rules are
      # rebuilt from scratch on every boot, so don't auto-save the build-time set).
      "echo iptables-persistent iptables-persistent/autosave_v4 boolean false | sudo debconf-set-selections",
      "echo iptables-persistent iptables-persistent/autosave_v6 boolean false | sudo debconf-set-selections",
      # Bake the AC's complete runtime package set into the AMI. netcat-openbsd
      # (nc, used by the frps-control bind check) and iptables-persistent were
      # the only two the AC installed at boot but did NOT bake — forcing an
      # unconditional `apt-get update` on every launch. Baking them here lets
      # user_data.sh.tpl skip apt entirely, making AC boot independent of the
      # public Ubuntu mirror.
      "apt_get_with_retry install -y docker.io jq curl unzip gettext-base iptables ipset python3-cryptography ca-certificates netcat-openbsd iptables-persistent",
      "sudo systemctl enable docker",
      "sudo systemctl start docker",
    ]
  }

  # Install AWS CLI v2 (more reliable than apt version)
  provisioner "shell" {
    inline_shebang = "/bin/bash"
    inline = [
      "set -euo pipefail",
      "echo 'Installing AWS CLI v2...'",
      "curl -sL 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o /tmp/awscliv2.zip",
      "unzip -q /tmp/awscliv2.zip -d /tmp",
      "sudo /tmp/aws/install",
      "rm -rf /tmp/aws /tmp/awscliv2.zip",
      "aws --version",
    ]
  }

  # Create directories with proper permissions
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /opt/layerv/nhp-ac/etc",
      "sudo mkdir -p /opt/layerv/nhp-ac/log",
      "sudo mkdir -p /opt/layerv/traefik/plugins-local/src",
      "sudo mkdir -p /var/log/traefik",
      "sudo mkdir -p /acme",
      "sudo chmod 700 /acme",
    ]
  }

  # Login to ECR and extract binaries
  provisioner "shell" {
    inline_shebang = "/bin/bash"
    inline = var.runtime_packages_only ? [
      "set -euo pipefail",
      "echo 'Skipping AC binary extraction (runtime_packages_only=true); Terraform user_data pulls the active AC image at boot.'",
      ] : [
      "set -euo pipefail",
      "echo 'Extracting binaries from ECR...'",
      "if [ -z \"${var.image_tag}\" ]; then echo 'ERROR: image_tag is required when runtime_packages_only=false'; exit 1; fi",
      "ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)",
      "ECR_REPO=${var.ecr_repo != "" ? var.ecr_repo : "$ACCOUNT_ID.dkr.ecr.${var.aws_region}.amazonaws.com/layerv-nhp-${var.environment}-ac"}",
      "",
      "aws ecr get-login-password --region ${var.aws_region} | sudo docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.${var.aws_region}.amazonaws.com",
      "",
      "sudo docker pull $ECR_REPO:${var.image_tag}",
      "CONTAINER_ID=$(sudo docker create $ECR_REPO:${var.image_tag})",
      "",
      "# Extract Traefik binary",
      "sudo docker cp $CONTAINER_ID:/usr/local/bin/traefik /usr/local/bin/traefik",
      "sudo chmod +x /usr/local/bin/traefik",
      "",
      "# Extract nhp-ac binary and config",
      "sudo docker cp $CONTAINER_ID:/nhp-ac /opt/layerv/nhp-ac-extracted || true",
      "if [ -d /opt/layerv/nhp-ac-extracted ]; then",
      "  sudo cp -r /opt/layerv/nhp-ac-extracted/* /opt/layerv/nhp-ac/",
      "  sudo rm -rf /opt/layerv/nhp-ac-extracted",
      "fi",
      "",
      "# Extract iptables defaults script",
      "sudo docker cp $CONTAINER_ID:/iptables_defaults.sh /opt/layerv/nhp-ac/iptables_defaults.sh || true",
      "sudo chmod +x /opt/layerv/nhp-ac/iptables_defaults.sh 2>/dev/null || true",
      "",
      "sudo docker rm $CONTAINER_ID",
      "",
      "# Remove Docker image to save space",
      "sudo docker rmi $ECR_REPO:${var.image_tag} || true",
      "echo 'Binaries extracted successfully'",
    ]
  }

  # Download Traefik plugins from S3
  provisioner "shell" {
    inline_shebang = "/bin/bash"
    inline = var.runtime_packages_only ? [
      "set -euo pipefail",
      "echo 'Skipping Traefik plugin embedding (runtime_packages_only=true); Terraform user_data downloads configured plugins at boot.'",
      ] : [
      "set -euo pipefail",
      "echo 'Downloading Traefik plugins from S3...'",
      "if [ -z \"${var.plugin_bucket}\" ]; then echo 'ERROR: plugin_bucket is required when runtime_packages_only=false'; exit 1; fi",
      "for PLUGIN in ${join(" ", var.traefik_plugins)}; do",
      "  echo \"Downloading plugin: $PLUGIN (version: ${var.plugin_version})\"",
      "  sudo mkdir -p /opt/layerv/traefik/plugins-local/src/$PLUGIN",
      "  aws s3 sync s3://${var.plugin_bucket}/traefik/$PLUGIN/${var.plugin_version}/ /opt/layerv/traefik/plugins-local/src/$PLUGIN/ || {",
      "    echo \"Warning: Could not download $PLUGIN plugin\"",
      "  }",
      "done",
      "echo 'Plugins downloaded successfully'",
    ]
  }

  # Create systemd services
  provisioner "shell" {
    inline = [
      "echo 'Creating systemd service files...'",
      "",
      "# Traefik service",
      "sudo tee /etc/systemd/system/traefik.service > /dev/null << 'EOF'",
      "[Unit]",
      "Description=Traefik HTTPS Proxy",
      "Documentation=https://doc.traefik.io/traefik/",
      "After=network-online.target",
      "Wants=network-online.target",
      "",
      "[Service]",
      "Type=simple",
      "User=root",
      "ExecStart=/usr/local/bin/traefik --configFile=/opt/layerv/traefik/traefik.toml",
      "Restart=always",
      "RestartSec=5",
      "LimitNOFILE=65536",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",
      "",
      "# nhp-acd service",
      "sudo tee /etc/systemd/system/nhp-acd.service > /dev/null << 'EOF'",
      "[Unit]",
      "Description=NHP Access Controller Daemon",
      "Documentation=https://github.com/OpenNHP/opennhp",
      "After=network.target",
      "",
      "[Service]",
      "Type=simple",
      "User=root",
      "WorkingDirectory=/opt/layerv/nhp-ac",
      "ExecStart=/opt/layerv/nhp-ac/nhp-acd run",
      "Restart=always",
      "RestartSec=10",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",
      "",
      "sudo systemctl daemon-reload",
    ]
  }

  # Create first-boot configuration script for customers
  provisioner "shell" {
    inline = [
      "echo 'Creating first-boot configuration script...'",
      "",
      "sudo tee /opt/layerv/configure-nhp-ac.sh > /dev/null << 'SCRIPT'",
      "#!/bin/bash",
      "# LayerV NHP AC First-Boot Configuration",
      "# This script is called from user_data to configure the instance",
      "#",
      "# Required environment variables (set in user_data):",
      "#   DOMAIN_NAME     - Domain for Traefik certificates (e.g., app.example.com)",
      "#   ACME_EMAIL      - Email for Let's Encrypt registration",
      "#   NHP_SERVER_HOST - NHP Server hostname or IP",
      "#   NHP_SERVER_PORT - NHP Server port (default: 62206)",
      "#",
      "# Optional:",
      "#   NHP_SERVER_PUBKEY - NHP Server public key (base64)",
      "#   BACKEND_URL       - Backend service URL to proxy to",
      "",
      "set -e",
      "",
      "echo '=== LayerV NHP AC Configuration ==='",
      "",
      "# Validate required variables",
      "if [ -z \"$DOMAIN_NAME\" ]; then",
      "  echo 'ERROR: DOMAIN_NAME is required'",
      "  exit 1",
      "fi",
      "",
      "if [ -z \"$ACME_EMAIL\" ]; then",
      "  echo 'ERROR: ACME_EMAIL is required'",
      "  exit 1",
      "fi",
      "",
      "echo \"Configuring for domain: $DOMAIN_NAME\"",
      "",
      "# Generate Traefik configuration",
      "cat > /opt/layerv/traefik/traefik.toml << EOF",
      "[entryPoints]",
      "  [entryPoints.web]",
      "    address = \":80\"",
      "    [entryPoints.web.http.redirections.entryPoint]",
      "      to = \"websecure\"",
      "      scheme = \"https\"",
      "  [entryPoints.websecure]",
      "    address = \":443\"",
      "",
      "[certificatesResolvers.letsencrypt.acme]",
      "  email = \"$ACME_EMAIL\"",
      "  storage = \"/acme/acme.json\"",
      "  [certificatesResolvers.letsencrypt.acme.httpChallenge]",
      "    entryPoint = \"web\"",
      "",
      "[providers.file]",
      "  directory = \"/opt/layerv/traefik/conf.d\"",
      "  watch = true",
      "",
      "[experimental.localPlugins.nhp-token-validator]",
      "  moduleName = \"nhp-token-validator\"",
      "EOF",
      "",
      "# Create dynamic config directory",
      "mkdir -p /opt/layerv/traefik/conf.d",
      "",
      "# Enable and start services",
      "systemctl enable traefik nhp-acd",
      "systemctl start traefik nhp-acd",
      "",
      "echo '=== Configuration Complete ==='",
      "echo \"Domain: $DOMAIN_NAME\"",
      "echo 'Services: traefik, nhp-acd'",
      "SCRIPT",
      "sudo chmod +x /opt/layerv/configure-nhp-ac.sh",
    ]
  }

  # Security hardening for Marketplace
  provisioner "shell" {
    inline = [
      "echo 'Applying security hardening...'",
      "",
      "# Disable root login via SSH",
      "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
      "",
      "# Disable password authentication",
      "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
      "",
      "# Set proper permissions",
      "sudo chmod 700 /opt/layerv",
      "sudo chmod 755 /opt/layerv/nhp-ac",
      "sudo chmod 755 /opt/layerv/traefik",
    ]
  }

  # Final cleanup - CRITICAL for Marketplace
  provisioner "shell" {
    inline = [
      "echo 'Final cleanup for Marketplace compliance...'",
      "",
      "# Clean apt cache",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "",
      "# Clean temp files",
      "sudo rm -rf /tmp/*",
      "sudo rm -rf /var/tmp/*",
      "",
      "# Remove SSH host keys (regenerated on first boot)",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "",
      "# Clear machine-id (regenerated on first boot)",
      "sudo truncate -s 0 /etc/machine-id",
      "sudo rm -f /var/lib/dbus/machine-id",
      "",
      "# Remove any AWS credentials that might have been cached",
      "rm -rf ~/.aws",
      "sudo rm -rf /root/.aws",
      "",
      "# Clear bash history",
      "cat /dev/null > ~/.bash_history",
      "sudo cat /dev/null > /root/.bash_history",
      "history -c",
      "",
      "# Remove authorized_keys (Marketplace requirement)",
      "rm -f ~/.ssh/authorized_keys",
      "sudo rm -f /root/.ssh/authorized_keys",
      "",
      "# Clear cloud-init data (will re-run on first boot)",
      "sudo cloud-init clean --logs",
      "",
      "# Remove any log files",
      "sudo find /var/log -type f -exec truncate -s 0 {} \\;",
      "",
      "# Sync filesystem",
      "sync",
      "",
      "echo 'AMI build complete - ready for Marketplace submission!'",
    ]
  }

  # Persist the build artifact metadata so the next post-processor can publish
  # the bare AMI ID to the environment-specific SSM parameter Terraform reads.
  # Same manifest parsing pattern as nhp-server-docker.pkr.hcl; amazon-ebs
  # artifact IDs are "region:ami-xxx", which cannot be written to SSM as-is.
  post-processors {
    post-processor "manifest" {
      output     = "manifest-ac-${var.environment}.json"
      strip_path = true
      custom_data = {
        environment           = var.environment
        region                = var.aws_region
        git_sha               = var.git_sha
        runtime_packages_only = var.runtime_packages_only ? "true" : "false"
        publish_ssm           = var.publish_ssm ? "true" : "false"
      }
    }

    post-processor "shell-local" {
      inline_shebang = "/bin/bash"
      environment_vars = [
        "AWS_REGION=${var.aws_region}",
        "ENVIRONMENT=${var.environment}",
      ]
      inline = [
        "set -euo pipefail",
        "echo '=== Publishing AC AMI ID to SSM ==='",
        "MANIFEST=\"manifest-ac-$ENVIRONMENT.json\"",
        "if [ \"${var.publish_ssm}\" != \"true\" ]; then echo 'publish_ssm=false; leaving manifest for caller-managed SSM publish'; exit 0; fi",
        "trap 'rm -f \"$MANIFEST\"' EXIT",
        "if [ \"${var.marketplace}\" = \"true\" ]; then echo 'Marketplace build; skipping /$ENVIRONMENT/nhp/ac/ami-id publish'; exit 0; fi",
        "AMI_ID=$(\"${path.root}/../scripts/ami-id-from-manifest.sh\" \"$MANIFEST\" \"$AWS_REGION\")",
        "aws ssm put-parameter --region \"$AWS_REGION\" --name \"/$ENVIRONMENT/nhp/ac/ami-id\" --value \"$AMI_ID\" --type String --overwrite",
        "echo \"Published $AMI_ID to /$ENVIRONMENT/nhp/ac/ami-id\"",
      ]
    }
  }
}

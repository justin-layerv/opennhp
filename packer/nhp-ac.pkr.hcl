# Packer template for NHP AC AMI
# Builds an AMI with AC binaries and Traefik plugins pre-installed
#
# Usage:
#   packer init nhp-ac.pkr.hcl
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
      version = ">= 1.2.0"
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
  description = "Docker image tag to extract binaries from"
}

variable "ecr_repo" {
  type        = string
  default     = ""
  description = "ECR repository URL (defaults to layerv-nhp-{env}-ac)"
}

variable "plugin_bucket" {
  type        = string
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
  timestamp = formatdate("YYYYMMDD-hhmmss", timestamp())
  ami_name  = var.marketplace ? "${var.ami_name_prefix}-${var.product_version}" : "${var.ami_name_prefix}-${var.environment}-${local.timestamp}"

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
    ImageTag  = var.image_tag
    BuildTime = local.timestamp
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
    encrypted             = var.marketplace # Encrypt for Marketplace
  }

  # Marketplace requires specific snapshot settings
  snapshot_tags = local.all_tags
}

# ==================== Build ====================

build {
  sources = ["source.amazon-ebs.nhp-ac"]

  # Install base dependencies
  provisioner "shell" {
    inline = [
      "echo 'Installing base dependencies...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io jq curl unzip gettext-base iptables ipset python3-cryptography ca-certificates",
      "sudo systemctl enable docker",
    ]
  }

  # Install AWS CLI v2 (more reliable than apt version)
  provisioner "shell" {
    inline = [
      "echo 'Installing AWS CLI v2...'",
      "curl -sL 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o /tmp/awscliv2.zip",
      "unzip -q /tmp/awscliv2.zip -d /tmp",
      "sudo /tmp/aws/install",
      "rm -rf /tmp/aws /tmp/awscliv2.zip",
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
    inline = [
      "echo 'Extracting binaries from ECR...'",
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
    inline = [
      "echo 'Downloading Traefik plugins from S3...'",
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
}

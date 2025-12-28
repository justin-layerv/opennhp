# Packer template for NHP Server AMI
# Builds an AMI with NHP Server binary and plugins pre-installed
#
# Usage:
#   packer init nhp-server.pkr.hcl
#   packer build -var 'image_tag=abc123' -var 'plugin_bucket=layerv-nhp-sandbox-plugins' nhp-server.pkr.hcl
#
# This AMI is for INTERNAL USE ONLY (not AWS Marketplace).
# For customer deployments, they connect to LayerV-managed NHP Servers.
#
# Use cases:
# - Internal testing and development
# - Self-hosted enterprise deployments
# - Air-gapped environments
#
# Runtime: Native binary (no Docker required)

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
  description = "Environment name (sandbox, prod)"
}

variable "image_tag" {
  type        = string
  description = "Docker image tag to extract binary from"
}

variable "ecr_repo" {
  type        = string
  default     = ""
  description = "ECR repository URL (defaults to layerv-nhp-{env}-server)"
}

variable "plugin_bucket" {
  type        = string
  description = "S3 bucket containing plugins"
}

variable "server_plugins" {
  type        = list(string)
  default     = ["passcode", "oidc"]
  description = "List of NHP Server plugins to include"
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
  default     = "layerv-nhp-server"
  description = "Prefix for AMI name"
}

variable "ami_description" {
  type        = string
  default     = "LayerV NHP Server (internal use)"
  description = "AMI description"
}

# ==================== Locals ====================

locals {
  timestamp = formatdate("YYYYMMDD-hhmmss", timestamp())
  ami_name  = "${var.ami_name_prefix}-${var.environment}-${local.timestamp}"

  tags = {
    Name        = local.ami_name
    Environment = var.environment
    Component   = "nhp-server"
    ImageTag    = var.image_tag
    BuildTime   = local.timestamp
    ManagedBy   = "packer"
  }
}

# ==================== Source ====================

source "amazon-ebs" "nhp-server" {
  ami_name        = local.ami_name
  ami_description = var.ami_description
  instance_type   = var.instance_type
  region          = var.aws_region

  # Use latest Ubuntu 24.04 LTS
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

  tags     = local.tags
  run_tags = { Name = "packer-nhp-server-build" }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
  }
}

# ==================== Build ====================

build {
  sources = ["source.amazon-ebs.nhp-server"]

  # Install base dependencies (Docker only needed for build)
  provisioner "shell" {
    inline = [
      "echo 'Installing base dependencies...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io jq curl unzip ca-certificates",
      "sudo systemctl start docker",
    ]
  }

  # Install AWS CLI v2
  provisioner "shell" {
    inline = [
      "echo 'Installing AWS CLI v2...'",
      "curl -sL 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o /tmp/awscliv2.zip",
      "unzip -q /tmp/awscliv2.zip -d /tmp",
      "sudo /tmp/aws/install",
      "rm -rf /tmp/aws /tmp/awscliv2.zip",
    ]
  }

  # Create directories
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /opt/layerv/nhp-server/etc",
      "sudo mkdir -p /opt/layerv/nhp-server/logs",
      "sudo mkdir -p /opt/layerv/nhp-server/plugins",
    ]
  }

  # Extract NHP Server binary from Docker image
  provisioner "shell" {
    inline = [
      "echo 'Extracting NHP Server binary from ECR...'",
      "ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)",
      "ECR_REPO=${var.ecr_repo != "" ? var.ecr_repo : "$ACCOUNT_ID.dkr.ecr.${var.aws_region}.amazonaws.com/layerv-nhp-${var.environment}-server"}",
      "",
      "aws ecr get-login-password --region ${var.aws_region} | sudo docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.${var.aws_region}.amazonaws.com",
      "sudo docker pull $ECR_REPO:${var.image_tag}",
      "",
      "CONTAINER_ID=$(sudo docker create $ECR_REPO:${var.image_tag})",
      "sudo docker cp $CONTAINER_ID:/nhp-server /opt/layerv/nhp-server-extracted",
      "",
      "sudo cp /opt/layerv/nhp-server-extracted/nhp-server /opt/layerv/nhp-server/nhp-server",
      "sudo chmod +x /opt/layerv/nhp-server/nhp-server",
      "",
      "if [ -d /opt/layerv/nhp-server-extracted/etc ]; then",
      "  sudo cp -r /opt/layerv/nhp-server-extracted/etc/* /opt/layerv/nhp-server/etc/ 2>/dev/null || true",
      "fi",
      "",
      "sudo rm -rf /opt/layerv/nhp-server-extracted",
      "sudo docker rm $CONTAINER_ID",
      "sudo docker rmi $ECR_REPO:${var.image_tag}",
      "",
      "echo 'NHP Server binary extracted successfully'",
    ]
  }

  # Download NHP Server plugins from S3
  provisioner "shell" {
    inline = [
      "echo 'Downloading NHP Server plugins from S3...'",
      "for PLUGIN in ${join(" ", var.server_plugins)}; do",
      "  echo \"Downloading plugin: $PLUGIN (version: ${var.plugin_version})\"",
      "  sudo mkdir -p /opt/layerv/nhp-server/plugins/$PLUGIN/etc",
      "  aws s3 cp s3://${var.plugin_bucket}/nhp-server/$PLUGIN/${var.plugin_version}/main.so /opt/layerv/nhp-server/plugins/$PLUGIN/main.so || {",
      "    echo \"Warning: Could not download $PLUGIN plugin binary\"",
      "  }",
      "  sudo chmod 755 /opt/layerv/nhp-server/plugins/$PLUGIN/main.so 2>/dev/null || true",
      "done",
      "echo 'Plugins downloaded successfully'",
    ]
  }

  # Create systemd service
  provisioner "shell" {
    inline = [
      "echo 'Creating systemd service...'",
      "",
      "sudo tee /etc/systemd/system/nhp-server.service > /dev/null << 'EOF'",
      "[Unit]",
      "Description=LayerV NHP Server",
      "After=network-online.target",
      "Wants=network-online.target",
      "",
      "[Service]",
      "Type=simple",
      "User=root",
      "WorkingDirectory=/opt/layerv/nhp-server",
      "ExecStart=/opt/layerv/nhp-server/nhp-server",
      "Restart=always",
      "RestartSec=10",
      "LimitNOFILE=65536",
      "Environment=NHP_CONFIG_DIR=/opt/layerv/nhp-server/etc",
      "Environment=NHP_LOG_DIR=/opt/layerv/nhp-server/logs",
      "Environment=NHP_PLUGIN_DIR=/opt/layerv/nhp-server/plugins",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",
      "",
      "sudo systemctl daemon-reload",
    ]
  }

  # Cleanup
  provisioner "shell" {
    inline = [
      "echo 'Cleaning up...'",
      "",
      "# Remove Docker (not needed at runtime)",
      "sudo systemctl stop docker || true",
      "sudo apt-get purge -y docker.io containerd runc || true",
      "sudo apt-get autoremove -y",
      "sudo rm -rf /var/lib/docker",
      "",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo rm -rf /tmp/* /var/tmp/*",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "sudo truncate -s 0 /etc/machine-id",
      "",
      "echo 'AMI build complete'",
    ]
  }
}

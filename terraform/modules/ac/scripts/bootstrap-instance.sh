#!/bin/bash
# Bootstrap script for NHP AC instances
# Installs SSM agent and AWS CLI
set -e

# Detect OS
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
fi

echo "Detected OS: $OS"
echo ""

# ==================== SSM Agent ====================
echo "=== SSM Agent Setup ==="

case $OS in
  ubuntu|debian)
    # Ubuntu/Debian - use snap
    if ! command -v amazon-ssm-agent &> /dev/null; then
      echo "Installing SSM agent via snap..."
      snap install amazon-ssm-agent --classic
    fi
    systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent 2>/dev/null || true
    systemctl start snap.amazon-ssm-agent.amazon-ssm-agent 2>/dev/null || true
    ;;
  amzn|rhel|centos|fedora)
    # Amazon Linux / RHEL - usually pre-installed
    if ! systemctl is-active --quiet amazon-ssm-agent; then
      echo "Starting SSM agent..."
      systemctl enable amazon-ssm-agent
      systemctl start amazon-ssm-agent
    fi
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

echo "SSM agent status:"
systemctl status amazon-ssm-agent --no-pager 2>/dev/null || \
systemctl status snap.amazon-ssm-agent.amazon-ssm-agent --no-pager 2>/dev/null || \
echo "SSM agent status unknown"

echo ""

# ==================== AWS CLI ====================
echo "=== AWS CLI Setup ==="

# Check if AWS CLI is already installed
if command -v aws &> /dev/null; then
  echo "AWS CLI already installed:"
  aws --version
else
  echo "Installing AWS CLI..."

  case $OS in
    ubuntu|debian)
      # Try snap first (easiest on Ubuntu)
      if command -v snap &> /dev/null; then
        echo "Installing AWS CLI via snap..."
        snap install aws-cli --classic
      else
        # Fall back to pip
        echo "Installing AWS CLI via pip..."
        apt-get update -qq
        apt-get install -y -qq python3-pip unzip curl
        pip3 install awscli --quiet
      fi
      ;;
    amzn|rhel|centos|fedora)
      # Amazon Linux 2023 has AWS CLI pre-installed
      # For Amazon Linux 2 / RHEL
      if command -v yum &> /dev/null; then
        yum install -y awscli
      elif command -v dnf &> /dev/null; then
        dnf install -y awscli
      fi
      ;;
  esac

  # Verify installation
  if command -v aws &> /dev/null; then
    echo "AWS CLI installed successfully:"
    aws --version
  else
    # Try adding snap bin to PATH
    export PATH="/snap/bin:$PATH"
    if command -v aws &> /dev/null; then
      echo "AWS CLI available at /snap/bin/aws:"
      aws --version
    else
      echo "WARNING: AWS CLI installation may have failed"
    fi
  fi
fi

echo ""
echo "=== Setup Complete ==="

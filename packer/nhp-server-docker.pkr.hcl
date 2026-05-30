# Packer template for NHP Server Docker-optimized AMI
# Pre-installs Docker, AWS CLI, and dependencies to reduce instance startup time
# from ~5-6 minutes to ~30 seconds.
#
# Usage:
#   packer init nhp-server-docker.pkr.hcl
#   packer build -var 'environment=sandbox' nhp-server-docker.pkr.hcl
#
# After building, the AMI ID is automatically published to SSM parameter:
#   /{environment}/nhp/server/ami-id
#
# This naming aligns with the existing /${env}/nhp/server/* convention used
# by sibling parameters (image-tag, asg-name, active-color, ...).
# Terraform reads from this SSM parameter - no manual steps required.

packer {
  # Pin the Amazon plugin to a tight range so a surprise upstream release
  # can't change AMI build behaviour mid-rollout. The "~> 1.3" constraint
  # accepts any 1.3.x patch but rejects 1.4.x.
  #
  # Bump process (intentional, ~quarterly):
  #   1. Skim the plugin changelog at
  #      https://github.com/hashicorp/packer-plugin-amazon/releases
  #      for breaking changes since the current pin.
  #   2. Bump this constraint AND update `version:` on `hashicorp/setup-packer`
  #      in .github/workflows/build-and-push.yml in the SAME PR — the runner
  #      Packer version and the plugin's `required_packer_version` (if any)
  #      must agree.
  #   3. Run packer build against sandbox first; verify the resulting AMI
  #      boots cleanly before merging to main.
  # Periodic-bump tracking is at layervai/nhp issue (filed as a follow-up
  # from PR #252 round-3 review).
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
  description = "Environment name (sandbox, prod)"
}

variable "instance_type" {
  type        = string
  default     = "t3.medium"
  description = "Instance type for building"
}

variable "ami_name_prefix" {
  type        = string
  default     = "layerv-nhp-server-docker"
  description = "Prefix for AMI name"
}

variable "git_sha" {
  type        = string
  default     = "unknown"
  description = <<-EOT
    Git commit SHA at the time of the build. Used to tag the AMI and embed
    in the AMI name so an operator can grep an AMI back to the exact
    packer/* template version that produced it. CI passes this from
    $${{ github.sha }}. Local builds default to "unknown" — that's fine for
    local iteration but please pass a real SHA when building anything
    intended for production use.
  EOT
}

# ==================== Locals ====================

locals {
  timestamp = formatdate("YYYYMMDD-hhmmss", timestamp())
  # Embed a short git SHA in the AMI name so an operator who finds an AMI
  # in EC2 can grep it back to a commit. Falls back to "unknown" for local
  # builds where CI didn't pass git_sha.
  git_sha_short = substr(var.git_sha, 0, 7)
  ami_name      = "${var.ami_name_prefix}-${var.environment}-${local.timestamp}-${local.git_sha_short}"

  tags = {
    Name        = local.ami_name
    Environment = var.environment
    Component   = "nhp-server"
    Runtime     = "docker"
    BuildTime   = local.timestamp
    GitSHA      = var.git_sha
    ManagedBy   = "packer"
  }
}

# ==================== Source ====================

source "amazon-ebs" "nhp-server-docker" {
  ami_name        = local.ami_name
  ami_description = "LayerV NHP Server - Docker optimized (${var.environment})"
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
  run_tags = { Name = "packer-nhp-server-docker-build" }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    # Encrypt the AMI's root volume so any snapshot taken from this AMI
    # is also encrypted at rest. Defaults to the account's default EBS
    # KMS key, matching the encryption posture of Terraform-managed
    # launch templates that boot from this AMI.
    encrypted = true
  }
}

# ==================== Build ====================

build {
  sources = ["source.amazon-ebs.nhp-server-docker"]

  # Update package lists and install dependencies
  provisioner "shell" {
    inline = [
      "echo '=== Installing Docker and dependencies ==='",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io jq curl unzip ca-certificates",
      "sudo systemctl enable docker",
      "sudo systemctl start docker",
      "sudo usermod -aG docker ubuntu",
    ]
  }

  # Install AWS CLI v2
  #
  # Pinned to a specific version (not "latest") so a surprise upstream
  # release can't change AMI build behaviour mid-rollout. Same shape as
  # the Packer + Amazon plugin pin at the top of this file.
  #
  # Bump process (intentional, ~quarterly):
  #   1. Check https://github.com/aws/aws-cli/releases for the latest 2.x
  #      stable. Skim the changelog for breaking changes since the
  #      currently-pinned version.
  #   2. Verify the URL exists by manually downloading it once:
  #        curl -sI "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${NEW_VERSION}.zip"
  #      A 200 response confirms AWS still hosts that version (they keep
  #      old versions for years but it's worth a sanity check).
  #   3. Update the pinned version in the curl URL below.
  #   4. Run `packer build` against sandbox first; verify the resulting
  #      AMI's `aws --version` output matches the pinned version before
  #      merging to main.
  #
  # If you ever need to roll back, the previous pin lives in git history.
  provisioner "shell" {
    inline = [
      "echo '=== Installing AWS CLI v2 (pinned to 2.17.65) ==='",
      "curl -sL 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.17.65.zip' -o /tmp/awscliv2.zip",
      "unzip -q /tmp/awscliv2.zip -d /tmp",
      "sudo /tmp/aws/install",
      "rm -rf /tmp/aws /tmp/awscliv2.zip",
      "aws --version",
    ]
  }

  # Create NHP Server directories
  provisioner "shell" {
    inline = [
      "echo '=== Creating NHP Server directories ==='",
      "sudo mkdir -p /opt/layerv/nhp-server/etc",
      "sudo mkdir -p /opt/layerv/nhp-server/log",
      "sudo mkdir -p /opt/layerv/nhp-server/plugins",
    ]
  }

  # Configure DNS for Go's pure resolver.
  #
  # systemd-resolved must be restarted after writing the drop-in so the new
  # configuration takes effect at image-build time (the drop-in file alone
  # does not re-read on its own). Without the restart, the symlink swap may
  # race with the still-running stub listener and /etc/resolv.conf can end
  # up pointing at a file owned by the old process.
  provisioner "shell" {
    inline = [
      "echo '=== Configuring DNS ==='",
      "sudo mkdir -p /etc/systemd/resolved.conf.d",
      "sudo tee /etc/systemd/resolved.conf.d/disable-stub.conf > /dev/null << 'EOF'",
      "[Resolve]",
      "DNSStubListener=no",
      "EOF",
      "sudo systemctl restart systemd-resolved",
      "sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf",
      "echo '=== Verifying DNS resolution works ==='",
      "getent hosts archive.ubuntu.com >/dev/null || (echo 'DNS verification failed' && exit 1)",
    ]
  }

  # Cleanup.
  #
  # /etc/ssh/ssh_host_* are removed so every instance launched from this AMI
  # gets a unique SSH host identity instead of cloning the build host's keys.
  # We also clean the cloud-init instance state so cloud-init re-runs its
  # "first boot" modules on the target instance — including the
  # `ssh-host-keys-generate` module, which is what actually regenerates the
  # keys. Without clearing /var/lib/cloud/instances (and /var/lib/cloud/data),
  # cloud-init can treat the AMI boot as a "subsequent" boot on the builder
  # instance and skip key regeneration, leaving the instance with no host
  # keys at all.
  provisioner "shell" {
    inline = [
      "echo '=== Cleaning up ==='",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo rm -rf /tmp/* /var/tmp/*",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "sudo rm -rf /var/lib/cloud/instances/* /var/lib/cloud/instance",
      "sudo rm -rf /var/lib/cloud/data/*",
      "sudo truncate -s 0 /etc/machine-id",
      # Clear bash history (consistency with nhp-ac; #2254). truncate does the
      # write itself so it is root-safe via sudo; `sudo cat /dev/null >
      # /root/.bash_history` would fail — the `>` redirect runs as the
      # unprivileged login shell (see #2251).
      "truncate -s 0 ~/.bash_history",
      "sudo truncate -s 0 /root/.bash_history",
      # Sanity check: the Ubuntu cloud-init image must have the ssh module
      # enabled so the keys we just removed are regenerated on first boot.
      "grep -q '^\\s*-\\s*ssh\\s*$' /etc/cloud/cloud.cfg || (echo 'ssh module missing from cloud.cfg — keys would not regenerate' && exit 1)",
      "echo '=== AMI build complete ==='",
    ]
  }

  # Persist the build artifact metadata so the next post-processor can read it.
  # CRITICAL: do NOT use ${build.ID} for the SSM put-parameter value.
  # For amazon-ebs, build artifact ID is formatted as "region:ami-xxx" (or
  # comma-separated "region1:ami-a,region2:ami-b" for multi-region builds).
  # Pushing that string into SSM would make Terraform fail at apply time
  # with an InvalidAMIID.Malformed error. Instead we go through the
  # manifest post-processor, parse the AMI map with jq, and publish only
  # the bare ami-xxx for the current region.
  post-processors {
    post-processor "manifest" {
      # Per-environment manifest filename so two parallel matrix runs (e.g.
      # sandbox + prod via build-and-push.yml::packer-build) cannot collide
      # on a shared filesystem if anyone ever moves this off ephemeral
      # GitHub Actions runners. With the current ephemeral-runner setup
      # each matrix entry has its own filesystem and a fixed name would
      # also be safe, but the per-env name is cheap defensive hygiene.
      output     = "manifest-${var.environment}.json"
      strip_path = true
      custom_data = {
        environment = var.environment
        region      = var.aws_region
        git_sha     = var.git_sha
      }
    }

    post-processor "shell-local" {
      # IMPORTANT: do NOT use a multi-arg shebang here.
      #
      # An earlier version of this block had:
      #   inline_shebang = "/bin/bash -euo pipefail"
      # which works on macOS but FAILS on Linux. The Linux kernel passes
      # everything after the interpreter as ONE argument, so when bash
      # runs it sees "-euo pipefail" (single string with embedded space)
      # as a single token and rejects it with:
      #   /bin/bash: line 0: /bin/bash: ...: invalid option name
      # That's exactly what broke the post-#967 main run on the first
      # build that ever reached this post-processor (#252's earlier
      # latent bugs masked it for the entire #252 → #961 → #965 → #967
      # hotfix chain).
      #
      # Use a single-arg shebang and put `set -euo pipefail` as the
      # first inline command instead. Same strict-mode semantics, no
      # platform-specific shebang parsing.
      inline_shebang = "/bin/bash"
      environment_vars = [
        "AWS_REGION=${var.aws_region}",
        "ENVIRONMENT=${var.environment}",
      ]
      inline = [
        "set -euo pipefail",
        "echo '=== Publishing AMI ID to SSM ==='",
        "MANIFEST=\"manifest-$ENVIRONMENT.json\"",
        # Always clean up the manifest on exit, including the failure paths
        # below (no artifact_id, malformed AMI ID, or SSM put-parameter
        # failure). Without this trap a half-completed run leaves a stale
        # manifest on the runner that can confuse a retry.
        "trap 'rm -f \"$MANIFEST\"' EXIT",
        # The shared parser extracts the build-region ami-* from Packer's
        # region:ami-* artifact_id and dumps the manifest on malformed input.
        "AMI_ID=$(\"${path.root}/../scripts/ami-id-from-manifest.sh\" \"$MANIFEST\" \"$AWS_REGION\")",
        "aws ssm put-parameter --region \"$AWS_REGION\" --name \"/$ENVIRONMENT/nhp/server/ami-id\" --value \"$AMI_ID\" --type String --overwrite",
        "echo \"Published $AMI_ID to /$ENVIRONMENT/nhp/server/ami-id\"",
      ]
    }
  }
}

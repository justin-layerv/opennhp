# Plugin CI/CD Examples

This directory contains example GitHub Actions workflows for deploying plugins to the LayerV NHP infrastructure.

## Architecture

```
Plugin Repos                    S3 Bucket                    EC2 Instances
┌──────────────────┐           ┌────────────────────────┐   ┌────────────────┐
│ nhp-plugins-     │──build───►│ layerv-nhp-{env}-      │   │                │
│ passcode         │  upload   │ plugins/               │   │ NHP Server     │
└──────────────────┘           │ ├── nhp-server/        │◄──│ (downloads     │
                               │ │   ├── passcode/      │   │  at boot)      │
┌──────────────────┐           │ │   │   └── v1.0.0/    │   │                │
│ nhp-plugins-     │──build───►│ │   │       └── main.so│   └────────────────┘
│ oidc             │  upload   │ │   └── oidc/          │
└──────────────────┘           │ │       └── v1.0.0/    │   ┌────────────────┐
                               │ ├── traefik/           │   │                │
┌──────────────────┐           │ │   └── nhp-token-     │◄──│ AC / Traefik   │
│ traefik-plugins  │──build───►│ │       validator/     │   │ (downloads     │
│                  │  upload   │ │       └── v1.0.0/    │   │  at boot)      │
└──────────────────┘           │ └── configs/           │   │                │
                               │     └── (Terraform-    │   └────────────────┘
Terraform                      │         rendered)      │
┌──────────────────┐           └────────────────────────┘
│ plugins module   │──renders──►configs/*.toml
│ (version pins)   │
└──────────────────┘
```

## Workflows

### NHP Server Plugins (passcode, oidc)

Use `nhp-server-plugin.yml` for Go plugins that are loaded by NHP Server.

**Key points:**
- Build as Go plugin with `-buildmode=plugin`
- Must use same Go version as NHP Server
- Outputs `main.so` binary

### Traefik Plugins

Use `traefik-plugin.yml` for Traefik middleware plugins.

**Key points:**
- Traefik plugins are Go source files (not compiled)
- Must include `.traefik.yml` manifest
- Uploaded as directory of source files

## Prerequisites

1. **Terraform Deployment**: The `plugins` module must be deployed first:
   ```hcl
   # terraform.tfvars
   server_plugins = {
     passcode = {
       version = "v1.0.0"
       config = {
         ResourceMode = "api"
         AuthUrl      = "http://console:8888"
       }
     }
   }
   ```

2. **GitHub OIDC**: The `ecr` module creates the GitHub Actions IAM role automatically.

3. **Repository Secrets**:
   - `AWS_ACCOUNT_ID`: Sandbox AWS account ID
   - `AWS_ACCOUNT_ID_PROD`: Production AWS account ID

4. **GitHub Environments**:
   - `sandbox`: Auto-deploys on main branch push
   - `production`: Requires manual approval for tag releases

## Version Management

### Pinning Versions

In your Terraform configuration:
```hcl
server_plugins = {
  passcode = {
    version = "v1.2.0"  # Pin to specific version
    config  = { ... }
  }
}
```

### Deploying Updates

1. **Push to main**: Uploads to `latest/`
2. **Create tag** (e.g., `v1.2.0`): Uploads to both `v1.2.0/` and `latest/`
3. **Update Terraform**: Change version in tfvars, apply
4. **Trigger instance refresh**: New instances download updated plugins

### Rollback

```hcl
# Revert to previous version
server_plugins = {
  passcode = {
    version = "v1.1.0"  # Previous version
    config  = { ... }
  }
}
```

Then run `terraform apply` and trigger instance refresh.

## S3 Bucket Structure

```
s3://layerv-nhp-{env}-plugins/
├── nhp-server/
│   ├── passcode/
│   │   ├── v1.0.0/
│   │   │   └── main.so
│   │   ├── v1.1.0/
│   │   │   └── main.so
│   │   └── latest/
│   │       └── main.so
│   └── oidc/
│       └── ...
├── traefik/
│   └── nhp-token-validator/
│       ├── v1.0.0/
│       │   ├── .traefik.yml
│       │   ├── go.mod
│       │   └── *.go
│       └── latest/
│           └── ...
├── configs/
│   ├── nhp-server/
│   │   ├── passcode/
│   │   │   └── config.toml  (Terraform-rendered)
│   │   └── oidc/
│   │       └── config.toml
│   └── traefik/
│       └── ...
└── manifest.json  (plugin versions and S3 keys)
```

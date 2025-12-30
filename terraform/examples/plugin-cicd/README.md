# Plugin CI/CD Examples

This directory contains example GitHub Actions workflows for deploying **Traefik plugins** to the LayerV NHP infrastructure.

> **Note:** NHP Server plugins (passcode, oidc) are now **statically compiled** into the server binary.
> They no longer require separate CI/CD pipelines. See the [Architecture docs](../../../docs/ARCHITECTURE.md)
> for details on adding new server plugins.

## Architecture

```
                                    S3 Bucket                    EC2 Instances
                                    ┌────────────────────────┐   ┌────────────────┐
                                    │ layerv-nhp-{env}-      │   │                │
┌──────────────────┐                │ plugins/               │   │ NHP Server     │
│ traefik-plugins  │──upload───────►│ └── traefik/           │   │ (statically    │
│ repo             │                │     └── nhp-token-     │   │  compiled      │
└──────────────────┘                │         validator/     │   │  plugins)      │
                                    │         └── v1.0.0/    │   │                │
                                    │             ├── *.go   │   └────────────────┘
                                    │             └── ...    │
                                    │                        │   ┌────────────────┐
                                    │                        │   │                │
                                    │                        │◄──│ AC / Traefik   │
                                    │                        │   │ (downloads     │
                                    │                        │   │  at boot)      │
                                    └────────────────────────┘   └────────────────┘

NHP Server Plugins (passcode, oidc):
┌────────────────────────────────────────────────────────────────────────────────┐
│ endpoints/server/staticplugins/                                                │
│ ├── passcode/    ──┐                                                           │
│ └── oidc/        ──┼── Statically compiled into nhp-server binary              │
│                    │   No S3 upload, no separate CI/CD                         │
│                    │   Deploy via server Docker image + instance refresh       │
└────────────────────┴───────────────────────────────────────────────────────────┘
```

## Plugin Types

| Plugin Type | Location | Deployment Method |
|-------------|----------|-------------------|
| **NHP Server plugins** | `endpoints/server/staticplugins/` | Compiled into server binary, deployed via Docker image |
| **Traefik plugins** | External repo (`traefik-plugins`) | Uploaded to S3, downloaded by AC at boot |

## Workflows

### Traefik Plugins

Use `traefik-plugin.yml` for Traefik middleware plugins.

**Key points:**
- Traefik plugins are Go source files (not compiled binaries)
- Must include `.traefik.yml` manifest
- Uploaded as directory of source files to S3
- Traefik compiles them at runtime

## NHP Server Plugins (Static)

Server plugins are **NOT** deployed via CI/CD. Instead:

1. Plugin code lives in `endpoints/server/staticplugins/{plugin-name}/`
2. Plugin registers itself via `init()` function
3. Server `main.go` imports plugin with blank import
4. Plugin is compiled into server Docker image
5. Deploy via instance refresh

**Adding a new server plugin:**
```bash
# 1. Create plugin directory
mkdir -p endpoints/server/staticplugins/myplugin

# 2. Implement the plugin (must register in init())
# See passcode/ or oidc/ for examples

# 3. Add blank import in endpoints/server/main/main.go
import _ "github.com/OpenNHP/opennhp/endpoints/server/staticplugins/myplugin"

# 4. Add to server_plugins in terraform.tfvars
server_plugins = ["passcode", "oidc", "myplugin"]

# 5. Build and push server Docker image
# 6. Trigger instance refresh
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name layerv-nhp-sandbox-server-asg
```

## Prerequisites

1. **Terraform Deployment**: The `plugins` module must be deployed first:
   ```hcl
   # terraform.tfvars
   traefik_plugins = {
     nhp-token-validator = { version = "latest", config = {} }
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

### Traefik Plugins

In your Terraform configuration:
```hcl
traefik_plugins = {
  nhp-token-validator = {
    version = "v1.2.0"  # Pin to specific version
    config  = { ... }
  }
}
```

### Deploying Traefik Plugin Updates

1. **Push to main**: Uploads to `latest/`
2. **Create tag** (e.g., `v1.2.0`): Uploads to both `v1.2.0/` and `latest/`
3. **Update Terraform**: Change version in tfvars, apply
4. **Trigger instance refresh**: New AC instances download updated plugins

### Rollback

```hcl
# Revert to previous version
traefik_plugins = {
  nhp-token-validator = {
    version = "v1.1.0"  # Previous version
    config  = { ... }
  }
}
```

Then run `terraform apply` and trigger instance refresh.

## S3 Bucket Structure

```
s3://layerv-nhp-{env}-plugins/
├── traefik/
│   └── nhp-token-validator/
│       ├── v1.0.0/
│       │   ├── .traefik.yml
│       │   ├── go.mod
│       │   └── *.go
│       └── latest/
│           └── ...
├── configs/
│   └── traefik/
│       └── nhp-token-validator/
│           └── config.toml  (Terraform-rendered)
└── manifest.json  (plugin versions and S3 keys)
```

> **Note:** The `nhp-server/` directory is no longer used. Server plugins are
> statically compiled and don't need S3 storage.

# Console NHP Integration - Setup Notes

## Architecture

**Two domains required for NHP to work:**
1. `console.nhp.layerv.xyz` - Login page (Traefik BYPASS, not NHP protected)
2. `console2.apps.layerv.xyz` - Protected Console app (goes through nhp-acd)

**Flow:**
1. User visits `console.nhp.layerv.xyz` - loads login page (bypass route)
2. User logs in with username/password - Console API validates, returns JWT
3. Frontend calls `/plugins/passcode?action=auth_code&code={jwt}`
4. NHP Server validates JWT, performs knock to open `console2.apps.layerv.xyz`
5. NHP Server returns `redirect_url: https://console2.apps.layerv.xyz/`
6. Frontend redirects to protected Console app (now accessible after knock)

## Database Configuration (portal_sites)

The "console" resource in portal_sites needs:

```sql
-- site_url: Used by NHP SDK for redirect_url in auth_code response
-- This is where users are redirected after successful authentication
site_url = 'https://console2.apps.layerv.xyz/'

-- resources JSON (for knock routing)
resources = '[{"ac_id": "layerv-ac-tf", "hostname": "console2.apps.layerv.xyz", "ip": "<AC_NLB_IP>", "port": 443, "maskhost": true, "protocol": "tcp"}]'

-- ext_info JSON (for auth_code flow)
ext_info = '{
  "Title": "LayerV Console",
  "AuthUrl": "http://<console-internal-nlb>:8888/ps/custom_auth_api",
  "AppSecret": "layerv_secret_2025",
  "JWTSecret": "<jwt-signing-key>",
  "Method": "GET"
}'

-- service_info JSON (backend target for nhp-acd forwarding)
service_info = '{"ip": "<console-internal-nlb>", "port": 8888, "scheme": "http", "path": "/"}'
```

**Important**: The `redirect_url` in auth_code response comes from the `site_url` column, NOT from `ext_info.RedirectUrl`.

## Terraform Configuration

Set `console_protected_hostname` in tfvars to enable two-domain architecture:

```hcl
# terraform.tfvars
console_internal_only      = true
console_protected_hostname = "console2.apps.layerv.xyz"
```

The `protected_hostname` is used by `user_data.sh.tpl` to:
1. Set `site_url` to the protected domain (used for redirect_url in auth_code response)
2. Set `resources.hostname` to the protected domain (used for knock routing)

## DNS Setup

For sandbox: Create a specific `console2.apps.layerv.xyz` ALIAS record pointing to sandbox AC NLB.
The `*.apps.layerv.xyz` wildcard points to old infra, so we override with a specific record.

## Key Files

- `terraform/modules/console-ec2/user_data.sh.tpl` - Seeds portal_sites on boot
- `terraform/modules/console-ec2/variables.tf` - Console module variables (includes `protected_hostname`)
- `terraform/modules/ac/user_data.sh.tpl` - AC Traefik config with Console bypass

## Important Notes

1. **AC ID must match**: Resource `ac_id` must match AC registration (both use `layerv-ac-tf`)
2. **IP not DNS in resources**: The `ip` field in resources must be an actual IP (ipset fails with hostnames)
3. **DNS wildcard**: `*.apps.layerv.xyz` should point to AC NLB for protected resources
4. **Traefik bypass**: `console.nhp.layerv.xyz` has priority 20 bypass route to Console EC2

## Debugging

```bash
# Check NHP Server logs (inside Docker)
docker exec nhp-server cat /nhp-server/logs/server-$(date +%Y-%m-%d).log | tail -100

# Check AC logs
tail -100 /opt/layerv/nhp-ac/logs/ac-$(date +%Y-%m-%d).log

# Check portal_sites in RDS (site_url is the redirect target)
PGPASSWORD="$RDS_PASSWORD" psql -h "$RDS_HOST" -U portal -d portal -c "SELECT app_id, site_url, resources FROM portal_sites WHERE app_id = 'console';"
```

#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting Console EC2 installation at $(date)"
echo "Mode: ${internal_only ? "INTERNAL (behind AC/NHP)" : "EXTERNAL (public)"}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y

%{ if internal_only }
# Internal mode: minimal packages (no TLS/certbot needed)
apt-get install -y nginx docker.io curl jq unzip dnsutils
%{ else }
# External mode: full packages including certbot for TLS
apt-get install -y nginx certbot python3-certbot-nginx python3-certbot-dns-route53 docker.io curl jq unzip dnsutils
%{ endif }

# Install AWS CLI v2
if ! command -v aws &> /dev/null; then
  echo "Installing AWS CLI v2..."
  curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  rm -rf /tmp/aws /tmp/awscliv2.zip
fi
aws --version

# Start Docker
systemctl enable docker
systemctl start docker

# Wait for Docker to be ready
for i in {1..30}; do docker info && break || sleep 2; done

# ============================================================================
# Get RDS Credentials from Secrets Manager
# ============================================================================

echo "Fetching RDS credentials from Secrets Manager..."
REGION="${region}"
RDS_SECRET=$(aws secretsmanager get-secret-value --secret-id "${rds_secret_arn}" --region "$REGION" --query SecretString --output text)
RDS_USERNAME=$(echo "$RDS_SECRET" | jq -r '.username')
RDS_PASSWORD=$(echo "$RDS_SECRET" | jq -r '.password')

echo "RDS credentials retrieved"

%{ if internal_only }
# ============================================================================
# Internal Mode: Configure nginx for HTTP-only (AC handles TLS)
# ============================================================================

echo "Configuring nginx for internal mode (HTTP-only on port ${console_port})..."

cat > /etc/nginx/sites-available/console << 'NGINXEOF'
# Console API - Internal Mode nginx configuration
# Proxies HTTP from AC to Console Docker container
# TLS termination is handled by AC's Traefik
#
# Port mapping:
# - External (NLB): ${console_port} (8888)
# - Internal (Docker): 8080

upstream console_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

%{ if nhp_server_endpoint != null ~}
upstream nhp_server {
    server ${nhp_server_endpoint};
    keepalive 16;
}
%{ endif ~}

server {
    listen ${console_port};
    server_name ${domain_name} _;

    # Logging
    access_log /var/log/nginx/console-access.log;
    error_log /var/log/nginx/console-error.log;

    # Health check endpoint (for NLB health checks)
    location /health {
        access_log off;
        return 200 'OK';
        add_header Content-Type text/plain;
    }

%{ if nhp_server_endpoint != null ~}
    # NHP Server plugins endpoint (for auth_code action after Console login)
    # Routes /plugins/* to NHP Server HTTP endpoint
    location /plugins/ {
        proxy_pass http://nhp_server;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
%{ endif ~}

    # Proxy all other requests to Console
    location / {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # For file uploads
        client_max_body_size 50M;
    }
}
NGINXEOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/console /etc/nginx/sites-enabled/

nginx -t
systemctl enable nginx
systemctl restart nginx

echo "nginx configured for internal mode (HTTP on port ${console_port})"

%{ else }
# ============================================================================
# External Mode: Configure nginx with TLS via Let's Encrypt
# ============================================================================

echo "Configuring nginx (initial HTTP config for certbot)..."

cat > /etc/nginx/sites-available/console << 'NGINXEOF'
# Console - Initial HTTP config for Let's Encrypt

server {
    listen 80;
    server_name ${domain_name};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
NGINXEOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/console /etc/nginx/sites-enabled/

nginx -t
systemctl enable nginx
systemctl restart nginx

echo "nginx started with initial HTTP config"

# ============================================================================
# Obtain Let's Encrypt Certificate
# ============================================================================

echo "Obtaining Let's Encrypt certificate for ${domain_name}..."
sleep 5

%{ if hosted_zone_id != null }
# Use DNS-01 challenge with Route 53
certbot certonly \
    --dns-route53 \
    --dns-route53-propagation-seconds 60 \
    -d "${domain_name}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring
%{ else }
# Use HTTP-01 challenge
certbot certonly \
    --webroot \
    --webroot-path /var/www/html \
    -d "${domain_name}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring
%{ endif }

# Fallback to self-signed if certbot fails
if [ ! -f "/etc/letsencrypt/live/${domain_name}/fullchain.pem" ]; then
    echo "WARNING: Failed to obtain Let's Encrypt certificate, using self-signed"
    mkdir -p /etc/letsencrypt/live/${domain_name}
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/letsencrypt/live/${domain_name}/privkey.pem \
        -out /etc/letsencrypt/live/${domain_name}/fullchain.pem \
        -subj "/CN=${domain_name}"
fi

echo "Certificate obtained"
%{ endif }

# ============================================================================
# Pull and Run Console Docker Container
# ============================================================================

echo "Pulling Console Docker image..."
CONSOLE_IMAGE="${console_image}"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${account_id}.dkr.ecr.${region}.amazonaws.com"
docker pull "$CONSOLE_IMAGE"

echo "Starting Console container..."
# Console app listens on port 8888 inside the container (from config.docker.yaml)
# Internal mode: nginx on host proxies from 8888 to container via host port 8080
# External mode: nginx proxies from ${console_port} to container via host port 8080
CONTAINER_PORT=8888
HOST_PORT=8080

docker run -d \
    --name console \
    --restart always \
    -p 127.0.0.1:$HOST_PORT:$CONTAINER_PORT \
    -e "GVA_CONFIG_SYSTEM_ADDR=$CONTAINER_PORT" \
    -e "GVA_CONFIG_SYSTEM_DBTYPE=pgsql" \
    -e "GVA_CONFIG_SYSTEM_COOKIEDOMAIN=${cookie_domain}" \
    -e "GVA_CONFIG_PGSQL_PATH=${rds_endpoint}" \
    -e "GVA_CONFIG_PGSQL_PORT=${rds_port}" \
    -e "GVA_CONFIG_PGSQL_DBNAME=${rds_database_name}" \
    -e "GVA_CONFIG_PGSQL_USERNAME=$RDS_USERNAME" \
    -e "GVA_CONFIG_PGSQL_PASSWORD=$RDS_PASSWORD" \
    -e "GVA_CONFIG_PGSQL_CONFIG=sslmode=require TimeZone=UTC" \
    -e "GVA_CONFIG_ACCESSCONTROLLERS=${ac_config_json}" \
    -e "GVA_AUTO_INIT=${auto_init}" \
%{ if admin_password != null ~}
    -e "GVA_ADMIN_PASSWORD=${admin_password}" \
%{ endif ~}
    "$CONSOLE_IMAGE"

# Wait for console to be healthy
echo "Waiting for Console to be healthy..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:$HOST_PORT/health | grep -q "ok"; then
        echo "Console is healthy"
        break
    fi
    sleep 5
done

%{ if !internal_only }
# ============================================================================
# External Mode: Configure nginx with HTTPS (final config)
# ============================================================================

echo "Configuring nginx with HTTPS..."

cat > /etc/nginx/sites-available/console << 'NGINXEOF'
# Console API - nginx configuration
# Proxies HTTPS to Console Docker container

upstream console_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

# HTTP - Redirect to HTTPS
server {
    listen 80;
    server_name ${domain_name};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS - Main server
server {
    listen 443 ssl http2;
    server_name ${domain_name};

    ssl_certificate /etc/letsencrypt/live/${domain_name}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain_name}/privkey.pem;

    # SSL configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Logging
    access_log /var/log/nginx/console-access.log;
    error_log /var/log/nginx/console-error.log;

    # Health check
    location /health {
        access_log off;
        return 200 'OK';
        add_header Content-Type text/plain;
    }

    # Proxy all requests to Console
    location / {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # For file uploads
        client_max_body_size 50M;
    }
}
NGINXEOF

nginx -t && systemctl reload nginx

echo "nginx configured with HTTPS proxy to Console"

# ============================================================================
# Setup Certificate Renewal
# ============================================================================

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh << 'HOOKEOF'
#!/bin/bash
systemctl reload nginx
HOOKEOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh

systemctl enable certbot.timer
systemctl start certbot.timer
%{ endif }

# ============================================================================
# Create Console Health Check Service
# ============================================================================

cat > /etc/systemd/system/console-health.service << 'SVCEOF'
[Unit]
Description=Console Health Monitor
After=docker.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do if ! docker ps | grep -q console; then docker start console 2>/dev/null || true; fi; sleep 30; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable console-health
systemctl start console-health

%{ if seed_console_resource }
# ============================================================================
# Seed Console Resource in RDS (for NHP protection)
# ============================================================================

echo "Seeding Console resource in RDS for NHP protection..."

# Install PostgreSQL client
apt-get install -y postgresql-client

# Build the SQL to insert Console portal site (idempotent - only if not exists)
# This creates the Console as a protected resource that AC/NHP Server can route to
CONSOLE_APP_ID="${console_app_id}"
CONSOLE_SITE_NAME="LayerV Console"
CONSOLE_SITE_URL="https://${console_app_id}${ac_domain}/"
CONSOLE_HOSTNAME="${console_app_id}${ac_domain}"
CONSOLE_INTERNAL_NLB="${console_internal_nlb}"
CONSOLE_PORT="${console_port}"
AC_NLB_DNS="${ac_nlb_dns}"
COOKIE_DOMAIN="${cookie_domain}"

# Resolve AC NLB DNS to an IP address for ipset rules
# ipset requires IP addresses, not hostnames
AC_NLB_IP=$(dig +short "$AC_NLB_DNS" | head -1)
if [ -z "$AC_NLB_IP" ]; then
    echo "ERROR: Failed to resolve AC NLB DNS '$AC_NLB_DNS' to IP address"
    exit 1
fi
echo "AC NLB DNS: $AC_NLB_DNS -> IP: $AC_NLB_IP"
%{ if auth_signing_key != null ~}
JWT_SECRET="${auth_signing_key}"
%{ else ~}
JWT_SECRET="$CONSOLE_APP_ID"
%{ endif ~}
OPENTIME=3600
TOKEN_EXPIRE=86400

# Build ServiceInfo JSON (backend target)
SERVICE_INFO=$(cat <<SRVEOF
{"ip": "$CONSOLE_INTERNAL_NLB", "port": $CONSOLE_PORT, "scheme": "http", "path": "/"}
SRVEOF
)

# Build Resources JSON (AC routing config)
# ac_id must match the AC module's ac_id for knock routing to work
# ip must be an actual IP address (not DNS) because AC uses it in ipset rules
RESOURCES=$(cat <<RESEOF
[{"ac_id": "${ac_id}", "hostname": "$CONSOLE_HOSTNAME", "ip": "$AC_NLB_IP", "port": 443, "maskhost": true, "protocol": "tcp"}]
RESEOF
)

# Build ExtInfo JSON (required by passcode plugin for auth_code flow)
# AuthUrl: Console's token validation endpoint called by NHP Server
# AppSecret: Must match the hardcoded value in Console's /ps/custom_auth_api endpoint
# Method: HTTP method for AuthUrl call
AUTH_URL="http://$CONSOLE_INTERNAL_NLB:$CONSOLE_PORT/ps/custom_auth_api"
APP_SECRET="layerv_secret_2025"
EXT_INFO=$(cat <<EXTEOF
{"Title": "LayerV Console", "JWTSecret": "$JWT_SECRET", "AuthUrl": "$AUTH_URL", "AppSecret": "$APP_SECRET", "Method": "GET"}
EXTEOF
)

# Run the seed SQL (upsert pattern - insert if not exists, update if exists)
PGPASSWORD="$RDS_PASSWORD" psql -h "${rds_endpoint}" -p ${rds_port} -U "$RDS_USERNAME" -d "${rds_database_name}" <<SQLEOF
-- Insert Console portal site if not exists
INSERT INTO portal_sites (
    created_at, updated_at, site_name, site_url, app_id, jwt_secret,
    cookie_domain, opentime, skip_auth, is_private, organization,
    service_info, resources, ext_info, grant_users, grant_groups, main_app_config,
    token_expire, status, category
)
SELECT
    NOW(), NOW(), '$CONSOLE_SITE_NAME', '$CONSOLE_SITE_URL', '$CONSOLE_APP_ID', '$JWT_SECRET',
    '$COOKIE_DOMAIN', $OPENTIME, false, false, 'LayerV',
    '$SERVICE_INFO'::jsonb, '$RESOURCES'::jsonb, '$EXT_INFO'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb,
    $TOKEN_EXPIRE, 'active', 'system'
WHERE NOT EXISTS (
    SELECT 1 FROM portal_sites WHERE app_id = '$CONSOLE_APP_ID'
);

-- Update existing Console portal site with correct ext_info (for existing deployments)
-- This ensures AuthUrl is set correctly for the auth_code flow
UPDATE portal_sites
SET
    updated_at = NOW(),
    ext_info = '$EXT_INFO'::jsonb,
    service_info = '$SERVICE_INFO'::jsonb,
    resources = '$RESOURCES'::jsonb,
    jwt_secret = '$JWT_SECRET'
WHERE app_id = '$CONSOLE_APP_ID';

-- Log the result
DO \$\$
BEGIN
    IF EXISTS (SELECT 1 FROM portal_sites WHERE app_id = '$CONSOLE_APP_ID') THEN
        RAISE NOTICE 'Console resource exists in portal_sites (app_id: %)', '$CONSOLE_APP_ID';
    ELSE
        RAISE NOTICE 'Failed to create Console resource';
    END IF;
END \$\$;
SQLEOF

if [ $? -eq 0 ]; then
    echo "Console resource seeded successfully in RDS"
else
    echo "WARNING: Failed to seed Console resource in RDS (may already exist or DB not ready)"
fi
%{ endif }

# ============================================================================
# Final Checks
# ============================================================================

echo "Performing final checks..."
systemctl status nginx --no-pager
docker ps

echo "Console EC2 installation complete at $(date)"
%{ if internal_only }
echo "Mode: Internal (NHP-protected via AC)"
echo "Internal endpoint: http://${domain_name}:${console_port}"
%{ else }
echo "Mode: External (public access)"
echo "API Endpoint: https://${domain_name}"
%{ endif }

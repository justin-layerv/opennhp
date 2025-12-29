#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting Demo Gateway installation at $(date)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx certbot python3-certbot-nginx python3-certbot-dns-route53 curl jq awscli

# ============================================================================
# Configure nginx - Initial HTTP-only config for certbot
# ============================================================================

echo "Configuring nginx (initial HTTP config for certbot)..."

# Create initial nginx config (HTTP only for ACME challenge)
cat > /etc/nginx/sites-available/demo-gateway << 'NGINXEOF'
# Demo Gateway - Initial HTTP config for Let's Encrypt
# This will be updated after certificate is obtained

server {
    listen 80;
    server_name ${domain_name} www.${domain_name};

    # Let's Encrypt ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Redirect all other HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}
NGINXEOF

# Enable the site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/demo-gateway /etc/nginx/sites-enabled/

# Test nginx config
nginx -t

# Start nginx
systemctl enable nginx
systemctl restart nginx

echo "nginx started with initial HTTP config"

# ============================================================================
# Obtain Let's Encrypt Certificate
# ============================================================================

echo "Obtaining Let's Encrypt certificate for ${domain_name}..."

# Wait for nginx to be fully ready
sleep 5

# For cross-account Route 53, certbot needs AWS credentials with AssumeRole
%{ if cross_account_route53_role_arn != null }
echo "Configuring cross-account Route 53 access..."
# Create AWS config for certbot to assume cross-account role
mkdir -p /root/.aws
cat > /root/.aws/config << 'AWSEOF'
[default]
region = ${region}

[profile route53]
role_arn = ${cross_account_route53_role_arn}
credential_source = Ec2InstanceMetadata
AWSEOF

# Use DNS-01 challenge with cross-account Route 53
AWS_PROFILE=route53 certbot certonly \
    --dns-route53 \
    --dns-route53-propagation-seconds 60 \
    -d "${domain_name}" \
    -d "www.${domain_name}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring

%{ else }
# Use HTTP-01 challenge (same account or no Route 53)
certbot certonly \
    --webroot \
    --webroot-path /var/www/html \
    -d "${domain_name}" \
    -d "www.${domain_name}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring

%{ endif }

# Check if certificate was obtained
if [ ! -f "/etc/letsencrypt/live/${domain_name}/fullchain.pem" ]; then
    echo "ERROR: Failed to obtain Let's Encrypt certificate"
    echo "Falling back to self-signed certificate for testing"

    mkdir -p /etc/letsencrypt/live/${domain_name}
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/letsencrypt/live/${domain_name}/privkey.pem \
        -out /etc/letsencrypt/live/${domain_name}/fullchain.pem \
        -subj "/CN=${domain_name}"
fi

echo "Certificate obtained successfully"

# ============================================================================
# Configure nginx - Final HTTPS config
# ============================================================================

echo "Configuring nginx with HTTPS..."

cat > /etc/nginx/sites-available/demo-gateway << 'NGINXEOF'
# Demo Gateway - nginx configuration
# Routes qurl.link/{appId} to NHP Server passcode plugin

# Upstream NHP Server for plugin HTTP requests
upstream nhp_server {
    server ${nhp_server_endpoint}:${nhp_server_port};
    keepalive 32;
}

# HTTP - Redirect to HTTPS (except ACME challenges)
server {
    listen 80;
    server_name ${domain_name} www.${domain_name};

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
    server_name ${domain_name} www.${domain_name};

    ssl_certificate /etc/letsencrypt/live/${domain_name}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain_name}/privkey.pem;

    # SSL configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (optional - enable after testing)
    # add_header Strict-Transport-Security "max-age=31536000" always;

    # Logging
    access_log /var/log/nginx/demo-gateway-access.log;
    error_log /var/log/nginx/demo-gateway-error.log;

    # Health check endpoint
    location /health {
        access_log off;
        return 200 'OK';
        add_header Content-Type text/plain;
    }

    # Root path - redirect to demo landing page
    location = / {
        return 301 ${fallback_url};
    }

    # Route /{appId} to passcode plugin login page
    # Example: qurl.link/fa2df -> /plugins/passcode?resid=fa2df&action=login
    location ~ ^/(?<resid>[a-zA-Z0-9_-]+)/?$ {
        proxy_pass http://nhp_server/plugins/passcode?resid=$resid&action=login;
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
    }

    # Proxy all /plugins/* requests to NHP Server
    # This handles action=valid, action=oauth, etc.
    location /plugins/ {
        proxy_pass http://nhp_server;
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
    }

    # Static files (if any)
    location /static/ {
        root /var/www/html;
    }
}
NGINXEOF

# Test and reload nginx
nginx -t && systemctl reload nginx

echo "nginx configured with HTTPS and upstream routing"

# ============================================================================
# Setup Certificate Renewal
# ============================================================================

echo "Setting up certificate auto-renewal..."

# Create renewal hook to reload nginx
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh << 'HOOKEOF'
#!/bin/bash
systemctl reload nginx
HOOKEOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh

# Enable certbot timer for auto-renewal
systemctl enable certbot.timer
systemctl start certbot.timer

echo "Certificate auto-renewal configured"

# ============================================================================
# Final Checks
# ============================================================================

echo "Performing final checks..."

# Check nginx status
systemctl status nginx --no-pager

# Test connectivity to upstream
curl -s --connect-timeout 5 "http://${nhp_server_endpoint}:${nhp_server_port}/health" || echo "Warning: NHP Server not reachable (may not be ready yet)"

echo "Demo Gateway installation complete at $(date)"
echo "Domain: https://${domain_name}"
echo "Upstream: http://${nhp_server_endpoint}:${nhp_server_port}"

#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting Console EC2 installation at $(date)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx certbot python3-certbot-nginx python3-certbot-dns-route53 docker.io curl jq unzip

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

# ============================================================================
# Configure nginx - Initial HTTP-only config for certbot
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

# ============================================================================
# Pull and Run Console Docker Container
# ============================================================================

echo "Pulling Console Docker image..."
CONSOLE_IMAGE="${console_image}"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${account_id}.dkr.ecr.${region}.amazonaws.com"
docker pull "$CONSOLE_IMAGE"

echo "Starting Console container..."
docker run -d \
    --name console \
    --restart always \
    -p 127.0.0.1:${console_port}:${console_port} \
    -e "GVA_CONFIG_SYSTEM_ADDR=${console_port}" \
    -e "GVA_CONFIG_SYSTEM_DBTYPE=pgsql" \
    -e "GVA_CONFIG_SYSTEM_COOKIEDOMAIN=${cookie_domain}" \
    -e "GVA_CONFIG_PGSQL_PATH=${rds_endpoint}" \
    -e "GVA_CONFIG_PGSQL_PORT=${rds_port}" \
    -e "GVA_CONFIG_PGSQL_DBNAME=${rds_database_name}" \
    -e "GVA_CONFIG_PGSQL_USERNAME=$RDS_USERNAME" \
    -e "GVA_CONFIG_PGSQL_PASSWORD=$RDS_PASSWORD" \
    -e "GVA_CONFIG_PGSQL_CONFIG=sslmode=require TimeZone=UTC" \
    -e "GVA_CONFIG_ACCESSCONTROLLERS=${ac_config_json}" \
    "$CONSOLE_IMAGE"

# Wait for console to be healthy
echo "Waiting for Console to be healthy..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:${console_port}/api/health | grep -q "ok"; then
        echo "Console is healthy"
        break
    fi
    sleep 5
done

# ============================================================================
# Configure nginx - Final HTTPS config
# ============================================================================

echo "Configuring nginx with HTTPS..."

cat > /etc/nginx/sites-available/console << 'NGINXEOF'
# Console API - nginx configuration
# Proxies HTTPS to Console Docker container

upstream console_backend {
    server 127.0.0.1:${console_port};
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

# ============================================================================
# Final Checks
# ============================================================================

echo "Performing final checks..."
systemctl status nginx --no-pager
docker ps

echo "Console EC2 installation complete at $(date)"
echo "API Endpoint: https://${domain_name}"

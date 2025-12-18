#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting NHP Server installation at $(date)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y awscli jq docker.io curl

systemctl enable docker
systemctl start docker

for i in {1..30}; do docker info && break || sleep 2; done

SECRET_ARN="${secret_arn}"
REGION="${region}"
SECRET=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "$REGION" --query SecretString --output text)
PRIVATE_KEY=$(echo "$SECRET" | jq -r ".privateKey")
HOSTNAME=$(echo "$SECRET" | jq -r ".hostname")

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)

mkdir -p /opt/layerv/nhp-server/etc
mkdir -p /opt/layerv/nhp-server/log

cat > /opt/layerv/nhp-server/etc/config.toml << CONFIGEOF
PrivateKeyBase64 = "$PRIVATE_KEY"
DefaultCipherScheme = 1
ListenIp = ""
ListenPort = 62206
Hostname = "$HOSTNAME"
LogLevel = 3
DisableAgentValidation = false

[webrtc]
Enable = false
CONFIGEOF

%{ if multi_tenant && etcd_endpoint != null }
# Configure etcd connection for multi-tenant
cat > /opt/layerv/nhp-server/etc/remote.toml << 'REMOTEEOF'
Provider = "etcd"
Key = "/nhp/config"
Endpoints = ["${etcd_endpoint}"]
REMOTEEOF
%{ else }
# Single-tenant mode: configure HTTP server locally
cat > /opt/layerv/nhp-server/etc/http.toml << 'HTTPEOF'
EnableHttp = true
EnableTLS = false
HttpListenIp = ""
HttpListenPort = 62206
HTTPEOF
%{ endif }

CLOUDMAP_SERVICE_ID="${cloudmap_service_id}"

cat > /opt/layerv/nhp-server/cloudmap-register.sh << 'CMEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
echo "Registering instance $INSTANCE_ID ($LOCAL_IP) with Cloud Map service $SERVICE_ID"
aws servicediscovery register-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --attributes "AWS_INSTANCE_IPV4=$LOCAL_IP,AVAILABILITY_ZONE=$AZ,NHP_PORT=62206" \
  --region "$REGION"
echo "Instance registered successfully"
CMEOF
chmod +x /opt/layerv/nhp-server/cloudmap-register.sh

cat > /opt/layerv/nhp-server/cloudmap-deregister.sh << 'CMEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
echo "Deregistering instance $INSTANCE_ID from Cloud Map service $SERVICE_ID"
aws servicediscovery deregister-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --region "$REGION" || true
echo "Instance deregistered"
CMEOF
chmod +x /opt/layerv/nhp-server/cloudmap-deregister.sh

cat > /opt/layerv/nhp-server/health-monitor.sh << 'HEALTHEOF'
#!/bin/bash
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
while true; do
  if docker ps | grep -q nhp-server; then
    HEALTH_STATUS="HEALTHY"
  else
    HEALTH_STATUS="UNHEALTHY"
  fi
  aws servicediscovery update-instance-custom-health-status \
    --service-id "$SERVICE_ID" \
    --instance-id "$INSTANCE_ID" \
    --status "$HEALTH_STATUS" \
    --region "$REGION" 2>/dev/null || true
  sleep 30
done
HEALTHEOF
chmod +x /opt/layerv/nhp-server/health-monitor.sh

cat > /etc/systemd/system/nhp-health-monitor.service << SVCEOF
[Unit]
Description=NHP Health Monitor (Cloud Map)
After=network.target docker.service nhp-cloudmap-register.service

[Service]
Type=simple
ExecStart=/opt/layerv/nhp-server/health-monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

cat > /etc/systemd/system/nhp-cloudmap-register.service << SVCEOF
[Unit]
Description=Register NHP Server with Cloud Map
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/layerv/nhp-server/cloudmap-register.sh
RemainAfterExit=yes
ExecStop=/opt/layerv/nhp-server/cloudmap-deregister.sh

[Install]
WantedBy=multi-user.target
SVCEOF

ECR_REPO="${server_repo_url}"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${account_id}.dkr.ecr.${region}.amazonaws.com"

docker pull "$ECR_REPO:latest" || docker pull "$ECR_REPO:${environment}" || echo "Warning: Could not pull image"

cat > /etc/systemd/system/nhp-server.service << SVCEOF
[Unit]
Description=LayerV NHP Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/docker stop nhp-server
ExecStartPre=-/usr/bin/docker rm nhp-server
ExecStart=/usr/bin/docker run --rm --name nhp-server \
  --net=host \
  -v /opt/layerv/nhp-server/etc:/nhp-server/etc:ro \
  -v /opt/layerv/nhp-server/log:/var/log/nhp \
  ${server_repo_url}:latest
ExecStop=/usr/bin/docker stop nhp-server

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable nhp-cloudmap-register nhp-health-monitor nhp-server
systemctl start nhp-cloudmap-register
systemctl start nhp-health-monitor
systemctl start nhp-server || echo "NHP server start deferred"

echo "NHP Server installation complete at $(date)"

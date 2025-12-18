#!/bin/bash
# seed-etcd.sh
# Seeds etcd with initial NHP configuration for multi-tenant mode
#
# Usage:
#   ./seed-etcd.sh <environment> [config-file]
#
# Examples:
#   ./seed-etcd.sh staging
#   ./seed-etcd.sh prod /path/to/custom-config.json
#
# Prerequisites:
#   - AWS CLI configured with appropriate profile
#   - etcdctl available (or use Docker)
#   - jq for JSON processing

set -euo pipefail

ENVIRONMENT="${1:-staging}"
CONFIG_FILE="${2:-$(dirname "$0")/etcd-seed-config.json}"
AWS_REGION="${AWS_REGION:-us-east-2}"
AWS_PROFILE="${AWS_PROFILE:-layerv}"

echo "Seeding etcd for environment: $ENVIRONMENT"
echo "Config file: $CONFIG_FILE"

# Get etcd endpoint from Terraform outputs
cd "$(dirname "$0")/../environments/$ENVIRONMENT"
ETCD_ENDPOINT=$(terraform output -raw etcd_endpoint 2>/dev/null || echo "")

if [ -z "$ETCD_ENDPOINT" ]; then
    echo "Error: Could not get etcd endpoint from Terraform outputs"
    echo "Make sure Terraform has been applied for $ENVIRONMENT"
    exit 1
fi

echo "etcd endpoint: $ETCD_ENDPOINT"

# Check if we can reach etcd through SSM (ECS exec)
echo "Connecting to etcd via ECS exec..."

# Get the etcd task ARN
CLUSTER_ARN=$(aws ecs list-clusters --region "$AWS_REGION" --query "clusterArns[?contains(@, 'etcd')]" --output text | head -1)
if [ -z "$CLUSTER_ARN" ]; then
    echo "Error: Could not find etcd ECS cluster"
    exit 1
fi

TASK_ARN=$(aws ecs list-tasks --cluster "$CLUSTER_ARN" --service-name "layerv-nhp-$ENVIRONMENT-etcd" --region "$AWS_REGION" --query 'taskArns[0]' --output text)
if [ -z "$TASK_ARN" ] || [ "$TASK_ARN" = "None" ]; then
    echo "Error: Could not find running etcd task"
    exit 1
fi

echo "Found etcd task: $TASK_ARN"

# Read config file and prepare etcd commands
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file not found: $CONFIG_FILE"
    echo "Creating default config..."
    cat > "$CONFIG_FILE" << 'EOF'
{
  "http": {
    "EnableHttp": true,
    "EnableTLS": false,
    "HttpListenIp": "",
    "HttpListenPort": 62206
  },
  "acs": {},
  "agents": {},
  "resources": {},
  "authservices": {}
}
EOF
fi

# Generate etcdctl commands
echo "Preparing etcd seed commands..."

# Create a temporary script to run inside the container
SEED_SCRIPT=$(cat << 'SEEDEOF'
#!/bin/sh
set -e
ETCDCTL="ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379"

# HTTP config
echo "Setting HTTP config..."
eval $ETCDCTL put /nhp/config/http '{"EnableHttp":true,"EnableTLS":false,"HttpListenIp":"","HttpListenPort":62206}'

# Placeholder for ACs (Access Controllers)
echo "Setting ACs config..."
eval $ETCDCTL put /nhp/config/acs '{}'

# Placeholder for Agents
echo "Setting Agents config..."
eval $ETCDCTL put /nhp/config/agents '{}'

# Placeholder for Resources
echo "Setting Resources config..."
eval $ETCDCTL put /nhp/config/resources '{}'

# Placeholder for Auth Services
echo "Setting Auth Services config..."
eval $ETCDCTL put /nhp/config/authservices '{}'

echo "Verifying seed data..."
eval $ETCDCTL get --prefix /nhp/config/ --keys-only

echo "etcd seeding complete!"
SEEDEOF
)

# Execute the seed script via ECS exec
echo "Executing seed script in etcd container..."
aws ecs execute-command \
    --cluster "$CLUSTER_ARN" \
    --task "$TASK_ARN" \
    --container "etcd" \
    --command "/bin/sh -c '$SEED_SCRIPT'" \
    --interactive \
    --region "$AWS_REGION"

echo ""
echo "etcd seeding completed successfully!"
echo ""
echo "To verify, you can run:"
echo "  aws ecs execute-command --cluster $CLUSTER_ARN --task $TASK_ARN --container etcd --command 'ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 get --prefix /nhp/config/' --interactive"

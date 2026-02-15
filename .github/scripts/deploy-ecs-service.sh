#!/bin/bash
# Deploy an ECS service by registering a new task definition revision.
#
# Instead of `--force-new-deployment` (which re-pulls the same image), this script
# creates a new task definition revision with the updated image tag. ECS circuit
# breaker handles automatic rollback if the new revision fails health checks.
#
# Usage: deploy-ecs-service.sh <ssm-prefix> <new-image-tag>
# Example: deploy-ecs-service.sh layerv-nhp-prod ae6f825
#
# Prerequisites:
#   - SSM parameters exist:
#       /<prefix>/qurl-api-image-tag
#       /<prefix>/qurl-ecs-cluster
#       /<prefix>/qurl-ecs-service
#   - IAM permissions:
#       ecs:RegisterTaskDefinition, ecs:UpdateService,
#       ecs:DescribeTaskDefinition, ecs:DescribeServices,
#       iam:PassRole, ssm:PutParameter, ssm:GetParameter
#
# What it does:
#   1. Updates SSM image tag parameter
#   2. Gets current task definition and replaces the image tag
#   3. Registers new task definition revision
#   4. Updates ECS service to use new task definition
#   5. Waits for service stability (ECS circuit breaker handles rollback)

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <ssm-prefix> <new-image-tag>"
  echo "  ssm-prefix:    SSM parameter prefix (e.g., layerv-nhp-prod)"
  echo "  new-image-tag: Docker image tag to deploy (e.g., commit SHA)"
  exit 1
fi

SSM_PREFIX="$1"
NEW_IMAGE_TAG="$2"
AWS_REGION="${AWS_REGION:-us-east-2}"

if [[ -z "$NEW_IMAGE_TAG" ]]; then
  echo "ERROR: new-image-tag cannot be empty"
  exit 1
fi

echo "============================================"
echo "ECS Service Deploy"
echo "============================================"
echo "SSM Prefix:  $SSM_PREFIX"
echo "Image Tag:   $NEW_IMAGE_TAG"
echo ""

# Step 1: Update SSM parameter with new image tag
SSM_IMAGE_TAG_PARAM="/${SSM_PREFIX}/qurl-api-image-tag"
echo "Step 1: Updating SSM parameter: $SSM_IMAGE_TAG_PARAM"
aws ssm put-parameter \
  --name "$SSM_IMAGE_TAG_PARAM" \
  --value "$NEW_IMAGE_TAG" \
  --type String \
  --overwrite \
  --region "$AWS_REGION"
echo "  SSM parameter updated: $SSM_IMAGE_TAG_PARAM = $NEW_IMAGE_TAG"
echo ""

# Step 2: Read ECS cluster and service names from SSM
echo "Step 2: Reading ECS cluster and service from SSM..."
ECS_CLUSTER=$(aws ssm get-parameter \
  --name "/${SSM_PREFIX}/qurl-ecs-cluster" \
  --query "Parameter.Value" --output text \
  --region "$AWS_REGION")
ECS_SERVICE=$(aws ssm get-parameter \
  --name "/${SSM_PREFIX}/qurl-ecs-service" \
  --query "Parameter.Value" --output text \
  --region "$AWS_REGION")

echo "  ECS Cluster: $ECS_CLUSTER"
echo "  ECS Service: $ECS_SERVICE"
echo ""

# Step 3: Get current task definition
echo "Step 3: Getting current task definition..."
CURRENT_TASK_DEF_ARN=$(aws ecs describe-services \
  --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" \
  --query "services[0].taskDefinition" --output text \
  --region "$AWS_REGION")

if [[ -z "$CURRENT_TASK_DEF_ARN" || "$CURRENT_TASK_DEF_ARN" == "None" ]]; then
  echo "ERROR: Could not find current task definition for service $ECS_SERVICE"
  exit 1
fi

echo "  Current task definition: $CURRENT_TASK_DEF_ARN"
CURRENT_TASK_DEF=$(aws ecs describe-task-definition \
  --task-definition "$CURRENT_TASK_DEF_ARN" \
  --query "taskDefinition" --output json \
  --region "$AWS_REGION")

# Extract current image for logging
CURRENT_IMAGE=$(echo "$CURRENT_TASK_DEF" | jq -r '.containerDefinitions[0].image // "unknown"')
echo "  Current image: $CURRENT_IMAGE"
echo ""

# Step 4: Replace image tag in container definitions
echo "Step 4: Creating new task definition with image tag: $NEW_IMAGE_TAG"

# Extract the image repo (everything before the last colon)
IMAGE_REPO=$(echo "$CURRENT_IMAGE" | sed 's/:[^:]*$//')
if [[ -z "$IMAGE_REPO" || "$IMAGE_REPO" == "$CURRENT_IMAGE" ]]; then
  echo "ERROR: Could not parse image repository from: $CURRENT_IMAGE"
  exit 1
fi
NEW_IMAGE="${IMAGE_REPO}:${NEW_IMAGE_TAG}"
echo "  New image: $NEW_IMAGE"

# Build new task definition JSON:
# - Replace image tag in all container definitions that use the same repo
# - Strip ECS-managed fields that cannot be passed to register-task-definition
NEW_TASK_DEF=$(echo "$CURRENT_TASK_DEF" | jq \
  --arg new_image "$NEW_IMAGE" \
  --arg repo "$IMAGE_REPO" \
  '.containerDefinitions = [.containerDefinitions[] | if (.image | startswith($repo + ":")) then .image = $new_image else . end] | del(.taskDefinitionArn, .revision, .status, .registeredAt, .registeredBy, .deregisteredAt, .compatibilities, .requiresAttributes)')
echo ""

# Step 5: Register new task definition
echo "Step 5: Registering new task definition revision..."
NEW_TASK_DEF_ARN=$(echo "$NEW_TASK_DEF" | aws ecs register-task-definition \
  --cli-input-json file:///dev/stdin \
  --query "taskDefinition.taskDefinitionArn" --output text \
  --region "$AWS_REGION")

echo "  New task definition: $NEW_TASK_DEF_ARN"
echo ""

# Step 6: Update ECS service to use new task definition
echo "Step 6: Updating ECS service..."
aws ecs update-service \
  --cluster "$ECS_CLUSTER" \
  --service "$ECS_SERVICE" \
  --task-definition "$NEW_TASK_DEF_ARN" \
  --query "service.deployments[*].{status: status, desired: desiredCount, running: runningCount, taskDef: taskDefinition}" \
  --output table \
  --region "$AWS_REGION"
echo ""

# Step 7: Wait for service stability with progress output
echo "Step 7: Waiting for ECS service to stabilize..."
echo "  (ECS circuit breaker will auto-rollback if health checks fail)"

WAIT_TIMEOUT=600  # 10 minutes
WAIT_INTERVAL=15
WAIT_ELAPSED=0

while [[ $WAIT_ELAPSED -lt $WAIT_TIMEOUT ]]; do
  DEPLOYMENT_STATUS=$(aws ecs describe-services \
    --cluster "$ECS_CLUSTER" \
    --services "$ECS_SERVICE" \
    --query "services[0].deployments" --output json \
    --region "$AWS_REGION" 2>/dev/null || echo "[]")

  PRIMARY_RUNNING=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "PRIMARY")] | .[0].runningCount // 0')
  PRIMARY_DESIRED=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "PRIMARY")] | .[0].desiredCount // 0')
  PRIMARY_PENDING=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "PRIMARY")] | .[0].pendingCount // 0')
  ACTIVE_COUNT=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "ACTIVE")] | length')
  ROLLOUT=$(echo "$DEPLOYMENT_STATUS" | jq -r '[.[] | select(.status == "PRIMARY")] | .[0].rolloutState // "unknown"')

  echo "  [${WAIT_ELAPSED}s] PRIMARY: ${PRIMARY_RUNNING}/${PRIMARY_DESIRED} running, ${PRIMARY_PENDING} pending | rollout: ${ROLLOUT} | draining: ${ACTIVE_COUNT}"

  if [[ "$ROLLOUT" == "COMPLETED" && "$PRIMARY_RUNNING" -eq "$PRIMARY_DESIRED" && "$ACTIVE_COUNT" -eq 0 ]]; then
    echo "  Service stable: all tasks running, rollout complete."
    break
  fi

  if [[ "$ROLLOUT" == "FAILED" ]]; then
    echo "ERROR: ECS deployment rollout FAILED (circuit breaker triggered rollback)"
    exit 1
  fi

  sleep "$WAIT_INTERVAL"
  WAIT_ELAPSED=$((WAIT_ELAPSED + WAIT_INTERVAL))
done

if [[ $WAIT_ELAPSED -ge $WAIT_TIMEOUT ]]; then
  echo "ERROR: Timed out waiting for ECS service stability (${WAIT_TIMEOUT}s)"
  echo "  Check ECS console for deployment status."
  exit 1
fi

echo ""
echo "============================================"
echo "ECS Service Deploy Complete"
echo "============================================"
echo "SSM Prefix:  $SSM_PREFIX"
echo "Image:       $NEW_IMAGE"
echo "Task Def:    $NEW_TASK_DEF_ARN"
echo "Service:     $ECS_SERVICE"
echo "Cluster:     $ECS_CLUSTER"

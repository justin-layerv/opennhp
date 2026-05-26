# FRPS Cloud Map Routing Policy Flip

Use this runbook when changing `cloud_map_routing_policy` for the qurl reverse tunnel server per-AZ Cloud Map services, especially the WEIGHTED to MULTIVALUE flip.

## Why This Needs A Runbook

AWS Cloud Map replaces a service when its DNS routing policy changes. The service name is stable, but the service ID changes.

FRPS instances now resolve the Cloud Map service ID from the stable service name at boot. That keeps Terraform from coupling launch template replacement to Cloud Map service replacement, but it also means an apply that replaces services does not automatically move already-running instances to the new service IDs. The fleet must be cycled after the apply.

## Service Impact

This is a destructive maintenance operation for the affected color. Unless traffic has already been shifted away, the color is unavailable from the pre-drain step, when the old services reach `InstanceCount=0`, until the post-apply instance refresh has registered fresh instances against the recreated services.

Schedule the window from the target environment's FRPS ASG instance refresh duration, plus plan/apply time and verification slack; do not assume this is only a Terraform apply. Run the pre-drain, apply, and refresh as one contiguous window. Do not leave the fleet drained between steps, and do not pause between the apply and the instance refresh. Any FRPS instance that launches after the old service is deleted and before the replacement is created can fail Cloud Map lookup and restart until the post-apply refresh launches against the recreated services. Any unrelated FRPS ASG launch, health-check replacement, or scaling event during that gap can hit the same crash-loop shape.

For production, prefer landing/enforcing the hard Cloud Map tag-drift guard tracked in #2178 before the cutover. At minimum, manually verify the `Environment` and `Service=qurl-reverse-tunnel-server` tags on every FRPS Cloud Map service immediately before the pre-drain; Register/Deregister IAM evaluates the live resource tags, not Terraform's last-known tags.

## Procedure

1. Run `terraform plan` and confirm the diff only replaces the intended `frps-*` Cloud Map services.
2. Confirm the ready-to-apply plan changes `cloud_map_routing_policy` as intended, then pre-drain the services that Terraform will replace until every old service has `InstanceCount=0`. Cloud Map refuses `DeleteService` while instances remain registered, and this flip is destroy-then-create by design.
3. If Terraform is already stuck on stale empty WEIGHTED services with the same names, manually delete only the empty stale services first, then rerun the plan.
4. Suspend unrelated launch/health replacement processes on the affected FRPS ASGs so an incidental ASG event cannot launch into the delete/recreate gap.
5. Apply the routing policy change. The affected color stays unavailable until step 6 repopulates the recreated services.
6. Resume the suspended ASG processes, then start an FRPS instance refresh or otherwise replace the FRPS ASG instances.
7. Confirm each fresh instance logs a line shaped like `Registering qurl-reverse-tunnel-server instance ... with Cloud Map service ...`.
8. Confirm every expected per-AZ Cloud Map service has at least one healthy registration.
9. Confirm the qurl-router / qurl-service upstream emission points at the expected per-AZ `frps-${suffix}` hosts.

### Pre-Drain Before Apply

Do this in an accepted maintenance window or after shifting traffic away from the color being replaced. Draining makes the old WEIGHTED services deletable; it is not optional for a healthy fleet.

One safe drain path is to stop the registration unit on every FRPS instance in every affected ASG/color. The unit's `ExecStop` runs `cloudmap-deregister.sh`. Scope the SSM target list to only the affected ASG/color when you are not intentionally draining both colors; for large fleets, a per-AZ staged drain can reduce blast radius while still requiring the final apply and refresh to stay contiguous.

```sh
sudo systemctl stop frps-cloudmap-register
```

For a fleet-wide drain, prefer SSM RunCommand over an interactive SSH loop. Fill `FRPS_ASG_NAMES` from the blue/green ASG names in Terraform output or the AWS console for the affected color(s).

```bash
set -euo pipefail
export AWS_REGION=us-east-2
export FRPS_ASG_NAMES="qurl-reverse-tunnel-server-blue qurl-reverse-tunnel-server-green"
: "${AWS_REGION:?export AWS_REGION before running this command}"
: "${FRPS_ASG_NAMES:?export FRPS_ASG_NAMES before running this command}"

instance_ids=$(aws autoscaling describe-auto-scaling-groups \
  --region "$AWS_REGION" \
  --auto-scaling-group-names $FRPS_ASG_NAMES \
  --query "AutoScalingGroups[].Instances[].InstanceId" \
  --output text)

if [ -z "$instance_ids" ] || [ "$instance_ids" = "None" ]; then
  echo "no FRPS instances found for ASGs: $FRPS_ASG_NAMES"
  exit 1
fi

aws ssm send-command \
  --region "$AWS_REGION" \
  --document-name AWS-RunShellScript \
  --instance-ids $instance_ids \
  --parameters commands='["sudo systemctl stop frps-cloudmap-register"]'
```

Then run the registration-count check below before applying. Proceed only when every service Terraform will replace reports `InstanceCount=0`; this is Cloud Map's server-side registration count, and the pre-drain is what drives it to zero. Green services are skip-friendly when blue/green is disabled or green standby is intentionally 0.

### Suspend Incidental ASG Activity

After the pre-drain reaches `InstanceCount=0` and immediately before the apply, suspend launch and health-replacement processes on the affected FRPS ASGs. This prevents unrelated ASG activity from launching an instance while Terraform is between old-service delete and new-service create. Resume these processes before starting the post-apply instance refresh.

```bash
export AWS_REGION=us-east-2
export FRPS_ASG_NAMES="qurl-reverse-tunnel-server-blue qurl-reverse-tunnel-server-green"
: "${AWS_REGION:?export AWS_REGION before running this command}"
: "${FRPS_ASG_NAMES:?export FRPS_ASG_NAMES before running this command}"

for asg_name in $FRPS_ASG_NAMES; do
  aws autoscaling suspend-processes \
    --region "$AWS_REGION" \
    --auto-scaling-group-name "$asg_name" \
    --scaling-processes Launch HealthCheck ReplaceUnhealthy
  echo "suspended incidental launch/health processes for $asg_name"
done
```

After the apply completes and before starting the instance refresh:

```bash
set -euo pipefail
: "${AWS_REGION:?export AWS_REGION before running this command}"
: "${FRPS_ASG_NAMES:?export FRPS_ASG_NAMES before running this command}"

for asg_name in $FRPS_ASG_NAMES; do
  aws autoscaling resume-processes \
    --region "$AWS_REGION" \
    --auto-scaling-group-name "$asg_name" \
    --scaling-processes Launch HealthCheck ReplaceUnhealthy
  echo "resumed incidental launch/health processes for $asg_name"
done
```

### Deleting Stale Empty Services

Use this only when Terraform is already blocked by stale same-name services from the failed replacement. Never delete a service with registered instances.

Confirm the suffix list from `frps_az_suffixes` in the target environment's tfvars or Terraform output before running this loop. Set `INCLUDE_GREEN=true` only when blue/green is enabled and green services exist.

```bash
export AWS_REGION=us-east-2
export NAMESPACE_ID=ns-xxxxxxxxxxxxxxxx
export EXPECTED_ENVIRONMENT=sandbox
export FRPS_AZ_SUFFIXES="a b c"
export INCLUDE_GREEN=true
: "${AWS_REGION:?export AWS_REGION before running this loop}"
: "${NAMESPACE_ID:?export NAMESPACE_ID before running this loop}"
: "${EXPECTED_ENVIRONMENT:?export EXPECTED_ENVIRONMENT before running this loop}"
: "${FRPS_AZ_SUFFIXES:?export FRPS_AZ_SUFFIXES before running this loop}"

service_names=()
for suffix in $FRPS_AZ_SUFFIXES; do
  service_names+=("frps-${suffix}")
  if [ "$INCLUDE_GREEN" = "true" ]; then
    service_names+=("frps-green-${suffix}")
  fi
done

for name in "${service_names[@]}"; do
  service_id=$(aws servicediscovery list-services \
    --region "$AWS_REGION" \
    --filters "Name=NAMESPACE_ID,Values=$NAMESPACE_ID,Condition=EQ" \
    --query "Services[?Name=='${name}'].Id | [0]" \
    --output text)

  if [ -z "$service_id" ] || [ "$service_id" = "None" ]; then
    echo "skip missing service $name"
    continue
  fi

  instance_count=$(aws servicediscovery get-service \
    --region "$AWS_REGION" \
    --id "$service_id" \
    --query "Service.InstanceCount" \
    --output text)

  if [ "$instance_count" != "0" ]; then
    echo "refusing to delete $name ($service_id): InstanceCount=$instance_count"
    continue
  fi

  service_arn=$(aws servicediscovery get-service \
    --region "$AWS_REGION" \
    --id "$service_id" \
    --query "Service.Arn" \
    --output text)

  service_tag=$(aws servicediscovery list-tags-for-resource \
    --region "$AWS_REGION" \
    --resource-arn "$service_arn" \
    --query "Tags[?Key=='Service'].Value | [0]" \
    --output text)

  environment_tag=$(aws servicediscovery list-tags-for-resource \
    --region "$AWS_REGION" \
    --resource-arn "$service_arn" \
    --query "Tags[?Key=='Environment'].Value | [0]" \
    --output text)

  if [ "$service_tag" != "qurl-reverse-tunnel-server" ] || [ "$environment_tag" != "$EXPECTED_ENVIRONMENT" ]; then
    echo "refusing to delete $name ($service_id): unexpected tags Service=$service_tag Environment=$environment_tag"
    continue
  fi

  aws servicediscovery delete-service \
    --region "$AWS_REGION" \
    --id "$service_id"
done
```

After deletion, rerun `terraform plan` and confirm Terraform creates the intended MULTIVALUE replacements before applying.

### Registration Count Check

Run this before apply to confirm the old services are drained (`InstanceCount=0`) and after the instance refresh starts to confirm the new services are populated (`InstanceCount>=1`). Green services are skip-friendly when blue/green is disabled or green standby is intentionally 0.

Confirm the suffix list from `frps_az_suffixes` in the target environment's tfvars or Terraform output before running this loop. Set `INCLUDE_GREEN=true` only when blue/green is enabled and green services exist.

```bash
export AWS_REGION=us-east-2
export NAMESPACE_ID=ns-xxxxxxxxxxxxxxxx
export FRPS_AZ_SUFFIXES="a b c"
export INCLUDE_GREEN=true
: "${AWS_REGION:?export AWS_REGION before running this loop}"
: "${NAMESPACE_ID:?export NAMESPACE_ID before running this loop}"
: "${FRPS_AZ_SUFFIXES:?export FRPS_AZ_SUFFIXES before running this loop}"

service_names=()
for suffix in $FRPS_AZ_SUFFIXES; do
  service_names+=("frps-${suffix}")
  if [ "$INCLUDE_GREEN" = "true" ]; then
    service_names+=("frps-green-${suffix}")
  fi
done

for name in "${service_names[@]}"; do
  service_id=$(aws servicediscovery list-services \
    --region "$AWS_REGION" \
    --filters "Name=NAMESPACE_ID,Values=$NAMESPACE_ID,Condition=EQ" \
    --query "Services[?Name=='${name}'].Id | [0]" \
    --output text)

  if [ -z "$service_id" ] || [ "$service_id" = "None" ]; then
    echo "MISSING $name"
    continue
  fi

  instance_count=$(aws servicediscovery get-service \
    --region "$AWS_REGION" \
    --id "$service_id" \
    --query "Service.InstanceCount" \
    --output text)

  echo "$name $service_id InstanceCount=$instance_count"
done
```

## Expected Failure Modes

- `FATAL: Cloud Map service lookup failed ...`: Cloud Map API, IAM, or network reachability failed after retries. This is distinct from a missing service.
- `FATAL: no Cloud Map service named ...`: the service name derived from AZ/color does not exist in the namespace. Check suffixes, blue/green color, and routing-policy replacement state.
- Empty-AZ CloudWatch alarms after apply: the services exist, but instances have not been refreshed and are still registered against old service IDs.

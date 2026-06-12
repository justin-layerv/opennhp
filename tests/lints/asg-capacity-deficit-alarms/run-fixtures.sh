#!/bin/bash
# run-fixtures.sh — exercise the #2041 ASG capacity-deficit alarm-shape
# checker against a clean mini Terraform tree and a regression fixture that
# reintroduces the old flat GroupUnHealthyInstanceCount alarm shape.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CHECKER="$REPO_ROOT/.github/scripts/check-asg-capacity-deficit-alarms.py"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

write_good_alarm() {
  local file="$1"
  local alarm_name="$2"
  local period="$3"
  local desired_stat="$4"
  local in_service_stat="$5"
  local evaluation_periods="${6:-2}"

  mkdir -p "$(dirname "$file")"
  cat >"$file" <<TF
resource "aws_cloudwatch_metric_alarm" "$alarm_name" {
  alarm_name          = "$alarm_name"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = $evaluation_periods
  datapoints_to_alarm = $evaluation_periods
  threshold           = 0
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "capacity_deficit"
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    return_data = true
  }

  metric_query {
    id = "desired"

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = $period
      stat        = "$desired_stat"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }

  metric_query {
    id = "in_service"

    metric {
      metric_name = "GroupInServiceInstances"
      namespace   = "AWS/AutoScaling"
      period      = $period
      stat        = "$in_service_stat"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }
}
TF
}

write_clean_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_good_alarm \
    "$terraform_root/modules/ac/blue_green.tf" \
    "ac_green_asg_unhealthy" \
    300 \
    "Minimum" \
    "Maximum"
  write_good_alarm \
    "$terraform_root/modules/canary-deployment/alarms.tf" \
    "canary_asg_unhealthy" \
    60 \
    "Average" \
    "Average" \
    "local.canary_asg_capacity_deficit_evaluation_periods"
  write_good_alarm \
    "$terraform_root/modules/compute/blue_green.tf" \
    "green_asg_unhealthy" \
    300 \
    "Minimum" \
    "Maximum"
  write_good_alarm \
    "$terraform_root/modules/qurl-reverse-tunnel-server/blue_green.tf" \
    "frps_green_asg_unhealthy" \
    300 \
    "Minimum" \
    "Maximum"
}

write_bad_flat_metric_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  cat >"$terraform_root/modules/canary-deployment/alarms.tf" <<'TF'
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  alarm_name          = "canary_asg_unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "GroupUnHealthyInstanceCount"
  namespace           = "AWS/AutoScaling"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = "fixture-asg"
  }
}
TF
}

write_bad_input_query_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  cat >"$terraform_root/modules/canary-deployment/alarms.tf" <<'TF'
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  alarm_name          = "canary_asg_unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "capacity_deficit"
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    return_data = true
  }

  metric_query {
    id          = "desired"
    return_data = true

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }

  metric_query {
    id = "in_service"

    metric {
      metric_name = "GroupInServiceInstances"
      namespace   = "AWS/AutoScaling"
      period      = 300
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }
}
TF
}

write_bad_duplicate_id_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  cat >"$terraform_root/modules/canary-deployment/alarms.tf" <<'TF'
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  alarm_name          = "canary_asg_unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 0
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "capacity_deficit"
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    return_data = true
  }

  metric_query {
    id = "desired"

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }

  metric_query {
    id = "desired"

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }

  metric_query {
    id = "in_service"

    metric {
      metric_name = "GroupInServiceInstances"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }
}
TF
}

write_bad_missing_query_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  cat >"$terraform_root/modules/canary-deployment/alarms.tf" <<'TF'
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  alarm_name          = "canary_asg_unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 0
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "capacity_deficit"
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    return_data = true
  }

  metric_query {
    id = "desired"

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }
}
TF
}

write_bad_canary_semantics_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  cat >"$terraform_root/modules/canary-deployment/alarms.tf" <<'TF'
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  alarm_name          = "canary_asg_unhealthy"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = 1
  treat_missing_data  = "breaching"

  metric_query {
    id          = "capacity_deficit"
    expression  = "desired - in_service"
    return_data = true
  }

  metric_query {
    id = "desired"

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/EC2"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }

  metric_query {
    id = "in_service"

    metric {
      metric_name = "GroupTotalInstances"
      namespace   = "AWS/AutoScaling"
      period      = 300
      stat        = "Average"

      dimensions = {
        InstanceId = "i-fixture"
      }
    }
  }
}
TF
}

write_bad_standby_stats_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  write_good_alarm \
    "$terraform_root/modules/ac/blue_green.tf" \
    "ac_green_asg_unhealthy" \
    300 \
    "Average" \
    "Average"
}

write_bad_missing_datapoints_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  cat >"$terraform_root/modules/canary-deployment/alarms.tf" <<'TF'
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  alarm_name          = "canary_asg_unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = local.canary_asg_capacity_deficit_evaluation_periods
  threshold           = 0
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "capacity_deficit"
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    return_data = true
  }

  metric_query {
    id = "desired"

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }

  metric_query {
    id = "in_service"

    metric {
      metric_name = "GroupInServiceInstances"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }
}
TF
}

write_bad_period_and_metric_block_tree() {
  local root="$1"
  local terraform_root="$root/terraform"

  write_clean_tree "$root"
  cat >"$terraform_root/modules/canary-deployment/alarms.tf" <<'TF'
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  alarm_name          = "canary_asg_unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = local.canary_asg_capacity_deficit_evaluation_periods
  datapoints_to_alarm = local.canary_asg_capacity_deficit_evaluation_periods
  threshold           = 0
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "capacity_deficit"
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    return_data = true
  }

  metric_query {
    id = "desired"

    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 0
      stat        = "Average"

      dimensions = {
        AutoScalingGroupName = "fixture-asg"
      }
    }
  }

  metric_query {
    id = "in_service"
  }
}
TF
}

expect_failure() {
  local name="$1"
  local root="$2"
  local log="$TMP/$name.log"
  local needle
  local status

  shift 2

  set +e
  python3 "$CHECKER" --terraform-root "$root/terraform" >"$log" 2>&1
  status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    echo "::error::$name fixture unexpectedly passed" >&2
    sed 's/^/    /' "$log" >&2
    exit 1
  fi

  for needle in "$@"; do
    if ! grep -qF "$needle" "$log"; then
      echo "::error::$name fixture did not report '$needle'" >&2
      sed 's/^/    /' "$log" >&2
      exit 1
    fi
  done
}

write_clean_tree "$TMP/clean"
python3 "$CHECKER" --terraform-root "$TMP/clean/terraform" >"$TMP/clean.log" 2>&1
if ! grep -qF "ASG capacity-deficit alarm shape check: OK" "$TMP/clean.log"; then
  echo "::error::clean fixture passed without the expected success marker" >&2
  sed 's/^/    /' "$TMP/clean.log" >&2
  exit 1
fi
echo "  PASS fixture=clean"

write_bad_flat_metric_tree "$TMP/bad-flat-metric"
expect_failure \
  "bad-flat-metric" \
  "$TMP/bad-flat-metric" \
  "canary_asg_unhealthy must not use top-level metric_name"

write_bad_input_query_tree "$TMP/bad-input-query"
expect_failure \
  "bad-input-query" \
  "$TMP/bad-input-query" \
  "canary_asg_unhealthy.desired must not set return_data = true"

write_bad_duplicate_id_tree "$TMP/bad-duplicate-id"
expect_failure \
  "bad-duplicate-id" \
  "$TMP/bad-duplicate-id" \
  "canary_asg_unhealthy duplicate metric_query id: desired"

write_bad_missing_query_tree "$TMP/bad-missing-query"
expect_failure \
  "bad-missing-query" \
  "$TMP/bad-missing-query" \
  "canary_asg_unhealthy missing metric_query id(s): in_service"

write_bad_canary_semantics_tree "$TMP/bad-canary-semantics"
expect_failure \
  "bad-canary-semantics" \
  "$TMP/bad-canary-semantics" \
  "canary_asg_unhealthy comparison_operator must be 'GreaterThanThreshold'" \
  "canary_asg_unhealthy threshold must be 0" \
  "canary_asg_unhealthy treat_missing_data must be 'notBreaching'" \
  "canary_asg_unhealthy evaluation_periods must be '\${local.canary_asg_capacity_deficit_evaluation_periods}'" \
  "canary_asg_unhealthy datapoints_to_alarm must equal evaluation_periods" \
  "canary_asg_unhealthy.capacity_deficit expression must be 'FILL(desired, 0) - FILL(in_service, 0)'" \
  "canary_asg_unhealthy.desired namespace must be 'AWS/AutoScaling'" \
  "canary_asg_unhealthy.in_service metric_name must be 'GroupInServiceInstances'" \
  "canary_asg_unhealthy.in_service period must be 60" \
  "canary_asg_unhealthy.in_service must dimension on AutoScalingGroupName" \
  "canary_asg_unhealthy.desired and canary_asg_unhealthy.in_service periods must match"

write_bad_standby_stats_tree "$TMP/bad-standby-stats"
expect_failure \
  "bad-standby-stats" \
  "$TMP/bad-standby-stats" \
  "ac_green_asg_unhealthy.desired stat must be 'Minimum'" \
  "ac_green_asg_unhealthy.in_service stat must be 'Maximum'"

write_bad_missing_datapoints_tree "$TMP/bad-missing-datapoints"
expect_failure \
  "bad-missing-datapoints" \
  "$TMP/bad-missing-datapoints" \
  "canary_asg_unhealthy must set datapoints_to_alarm"

write_bad_period_and_metric_block_tree "$TMP/bad-period-metric-block"
expect_failure \
  "bad-period-metric-block" \
  "$TMP/bad-period-metric-block" \
  "canary_asg_unhealthy.desired period must be a positive integer" \
  "canary_asg_unhealthy.in_service must contain exactly one metric block"

echo "asg-capacity-deficit-alarm fixtures: clean passed; bad fixtures failed as expected"

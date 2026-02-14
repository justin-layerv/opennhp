"""
AC Secret Reconciliation Lambda

Scheduled daily to clean up orphaned per-instance AC secrets in Secrets Manager.
When AC instances are terminated, their Secrets Manager entries (private keys)
are not automatically deleted. This Lambda:

1. Lists all per-instance AC secrets matching configured prefixes
2. Queries EC2 for all non-terminated instances
3. Deletes secrets whose instance IDs no longer exist
4. Publishes a custom CloudWatch metric for observability

Environment variables:
  SECRET_PREFIXES: JSON list of secret name prefixes (e.g., '["nhp-sandbox-ac-i-", "nhp-sandbox-console-ac-i-"]')
  RECOVERY_WINDOW_DAYS: Days before permanent deletion (0 = force delete immediately)
  DRY_RUN: Set to "true" to log deletions without executing them
"""

import json
import logging
import os
import re

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRET_PREFIXES = json.loads(os.environ.get("SECRET_PREFIXES", "[]"))
RECOVERY_WINDOW_DAYS = int(os.environ.get("RECOVERY_WINDOW_DAYS", "7"))
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")

# Instance IDs are 8-17 hex chars after "i-", anchored to end of secret name
INSTANCE_ID_PATTERN = re.compile(r"(i-[0-9a-f]{8,17})$")

# Adaptive retry mode handles throttling from sequential DeleteSecret calls
retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})

secretsmanager = boto3.client("secretsmanager", config=retry_config)
ec2 = boto3.client("ec2")
cloudwatch = boto3.client("cloudwatch")


def handler(event, context):
    """Entry point. Lists secrets, checks instances, deletes orphans, reports."""
    logger.info(
        "Starting AC secret reconciliation (prefixes=%s, recovery_window=%d, dry_run=%s)",
        SECRET_PREFIXES,
        RECOVERY_WINDOW_DAYS,
        DRY_RUN,
    )

    if not SECRET_PREFIXES:
        logger.error("SECRET_PREFIXES is empty, nothing to reconcile")
        raise ValueError("SECRET_PREFIXES environment variable must be a non-empty JSON list")

    # Step 1: List all per-instance AC secrets
    ac_secrets = list_ac_secrets(SECRET_PREFIXES)
    logger.info("Found %d per-instance AC secrets", len(ac_secrets))

    if not ac_secrets:
        publish_metric(0)
        return {"statusCode": 200, "body": json.dumps({"orphans_deleted": 0, "total_secrets": 0})}

    # Step 2: Get all live (non-terminated) instance IDs
    live_ids = get_live_instance_ids()
    logger.info("Found %d live instances", len(live_ids))

    # Step 3: Identify orphans
    orphans = [s for s in ac_secrets if s["instance_id"] not in live_ids]
    logger.info(
        "Identified %d orphaned secrets out of %d total", len(orphans), len(ac_secrets)
    )
    if orphans:
        orphan_ids = [o["instance_id"] for o in orphans]
        logger.info("Orphaned instance IDs: %s", orphan_ids[:50])

    # Step 4: Delete orphans
    deleted_count = delete_orphaned_secrets(orphans, RECOVERY_WINDOW_DAYS)

    # Step 5: Publish metric
    publish_metric(deleted_count)

    result = {
        "total_secrets": len(ac_secrets),
        "live_instances": len(live_ids),
        "orphans_found": len(orphans),
        "orphans_deleted": deleted_count,
        "dry_run": DRY_RUN,
    }
    logger.info("Reconciliation complete: %s", json.dumps(result))
    return {"statusCode": 200, "body": json.dumps(result)}


def list_ac_secrets(prefixes):
    """
    List all Secrets Manager secrets matching the given name prefixes.
    Secrets pending deletion are excluded by the API (IncludePlannedDeletion defaults to False).
    Returns list of {"name": str, "instance_id": str}.
    """
    secrets = []
    for prefix in prefixes:
        paginator = secretsmanager.get_paginator("list_secrets")
        page_iterator = paginator.paginate(
            Filters=[{"Key": "name", "Values": [prefix]}],
        )
        for page in page_iterator:
            for secret in page.get("SecretList", []):
                name = secret["Name"]
                match = INSTANCE_ID_PATTERN.search(name)
                if match:
                    secrets.append({"name": name, "instance_id": match.group(1)})
                else:
                    logger.warning("Could not extract instance ID from secret: %s", name)

    return secrets


def get_live_instance_ids():
    """
    Get all non-terminated EC2 instance IDs in the account/region.
    Returns a set of instance ID strings.
    """
    live_ids = set()
    paginator = ec2.get_paginator("describe_instances")
    page_iterator = paginator.paginate(
        Filters=[
            {
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped", "shutting-down"],
            }
        ]
    )
    for page in page_iterator:
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                live_ids.add(instance["InstanceId"])

    return live_ids


def delete_orphaned_secrets(orphans, recovery_window):
    """
    Delete orphaned secrets. If recovery_window is 0, force-delete immediately.
    Continues on individual failures.
    Returns the count of successfully deleted secrets.
    """
    deleted = 0
    for orphan in orphans:
        name = orphan["name"]
        instance_id = orphan["instance_id"]

        if DRY_RUN:
            logger.info("[DRY RUN] Would delete secret: %s (instance: %s)", name, instance_id)
            deleted += 1
            continue

        try:
            if recovery_window == 0:
                secretsmanager.delete_secret(
                    SecretId=name, ForceDeleteWithoutRecovery=True
                )
            else:
                secretsmanager.delete_secret(
                    SecretId=name, RecoveryWindowInDays=recovery_window
                )
            logger.info("Deleted secret: %s (instance: %s)", name, instance_id)
            deleted += 1
        except ClientError as e:
            logger.error(
                "Failed to delete secret %s: %s", name, e.response["Error"]["Message"]
            )

    return deleted


def publish_metric(count):
    """Publish OrphanedSecretsDeleted custom metric to CloudWatch."""
    try:
        cloudwatch.put_metric_data(
            Namespace="LayerV/NHP",
            MetricData=[
                {
                    "MetricName": "OrphanedSecretsDeleted",
                    "Dimensions": [
                        {"Name": "Environment", "Value": ENVIRONMENT},
                    ],
                    "Value": count,
                    "Unit": "Count",
                }
            ],
        )
        logger.info("Published metric OrphanedSecretsDeleted=%d", count)
    except ClientError as e:
        logger.error("Failed to publish metric: %s", e.response["Error"]["Message"])

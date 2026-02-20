"""CloudFront CIDR Drift Checker.

Compares the current AWS CloudFront origin-facing IP ranges against the
stored SSM parameter value. Publishes a CloudWatch metric indicating
whether the CIDRs are in sync (0) or drifted (1).

Triggered daily by EventBridge to detect when `terraform apply` is needed
to update the trusted proxy CIDRs after AWS publishes new CloudFront IPs.
"""

import json
import os
import urllib.error
import urllib.request

import boto3


def handler(event, context):
    ssm_param = os.environ["SSM_PARAMETER_NAME"]
    environment = os.environ["ENVIRONMENT"]
    region = os.environ.get("AWS_REGION", "us-east-2")

    # Fetch current CloudFront origin-facing CIDRs from AWS
    try:
        resp = urllib.request.urlopen(
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            timeout=10,
        )
        data = json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"Failed to fetch AWS IP ranges: {e}")
        raise
    current_cidrs = sorted(
        p["ip_prefix"]
        for p in data["prefixes"]
        if p["service"] == "CLOUDFRONT_ORIGIN_FACING"
    )

    # Get stored CIDRs from SSM
    ssm = boto3.client("ssm", region_name=region)
    param = ssm.get_parameter(Name=ssm_param)["Parameter"]["Value"]
    stored_cidrs = sorted(c.strip() for c in param.split(",") if c.strip())

    # Compare
    drifted = 1 if current_cidrs != stored_cidrs else 0

    # Publish metric
    cw = boto3.client("cloudwatch", region_name=region)
    cw.put_metric_data(
        Namespace="LayerV/NHP",
        MetricData=[
            {
                "MetricName": "CloudFrontCIDRDrift",
                "Dimensions": [
                    {"Name": "Environment", "Value": environment},
                ],
                "Value": drifted,
                "Unit": "Count",
            }
        ],
    )

    if drifted:
        added = set(current_cidrs) - set(stored_cidrs)
        removed = set(stored_cidrs) - set(current_cidrs)
        print(
            f"DRIFT DETECTED: {len(current_cidrs)} current vs "
            f"{len(stored_cidrs)} stored CIDRs"
        )
        if added:
            print(f"  Added CIDRs: {sorted(added)}")
        if removed:
            print(f"  Removed CIDRs: {sorted(removed)}")
        print("Run 'terraform apply' to update the SSM parameter.")
    else:
        print(f"CIDRs in sync: {len(current_cidrs)} CIDRs")

    return {
        "drifted": bool(drifted),
        "current_count": len(current_cidrs),
        "stored_count": len(stored_cidrs),
    }

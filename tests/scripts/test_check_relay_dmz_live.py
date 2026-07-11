#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import copy
import errno
import importlib.util
import io
import json
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check-relay-dmz-live.py"

spec = importlib.util.spec_from_file_location("check_relay_dmz_live", SCRIPT_PATH)
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def run_embedded_probe(script: str, *argv: str) -> int:
    """Execute the exact Python sent through SSM and return its exit code."""
    with mock.patch.object(sys, "argv", ["probe", *argv]):
        try:
            exec(compile(script, "<embedded-relay-probe>", "exec"), {})
        except SystemExit as exc:
            return int(exc.code)
    raise AssertionError("embedded probe returned without an explicit exit")


def rule(
    protocol: str, start: int | None, end: int | None, kind: str, source: str
) -> dict:
    return {
        "protocol": protocol,
        "from": start,
        "to": end,
        "source_type": kind,
        "source": source,
    }


def endpoint_policy(service: str) -> dict:
    environment = "sandbox"
    account_id = "767397897469"
    region = "us-east-2"
    deny = {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "*",
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:PrincipalAccount": account_id}},
    }
    if service == "ecr.api":
        allows = [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "ecr:GetAuthorizationToken",
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": sorted(
                    checker.EXPECTED_ENDPOINT_ACTIONS[service]
                    - {"ecr:GetAuthorizationToken"}
                ),
                "Resource": f"arn:aws:ecr:{region}:{account_id}:repository/layerv-nhp-{environment}-relay",
            },
        ]
    elif service == "ecr.dkr":
        allows = [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": sorted(checker.EXPECTED_ENDPOINT_ACTIONS[service]),
                "Resource": f"arn:aws:ecr:{region}:{account_id}:repository/layerv-nhp-{environment}-relay",
            }
        ]
    elif service == "ssm":
        allows = [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "ssm:GetParameter",
                "Resource": f"arn:aws:ssm:{region}:{account_id}:parameter/{environment}/nhp/relay/image-tag",
            },
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": sorted(
                    checker.EXPECTED_ENDPOINT_ACTIONS[service] - {"ssm:GetParameter"}
                ),
                "Resource": "*",
            },
        ]
    else:
        resources = {
            "secretsmanager": f"arn:aws:secretsmanager:{region}:{account_id}:secret:layerv-nhp-{environment}-relay-abc",
            "logs": f"arn:aws:logs:{region}:{account_id}:log-group:/layerv/nhp/{environment}/relay:*",
        }
        allow = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "*"
            if service == "guardduty-data"
            else sorted(checker.EXPECTED_ENDPOINT_ACTIONS[service]),
            "Resource": resources.get(service, "*"),
        }
        if service == "monitoring":
            allow["Condition"] = {
                "StringEquals": {"cloudwatch:namespace": "LayerV/NHP"}
            }
        allows = [allow]
    return {"Version": "2012-10-17", "Statement": [*allows, deny]}


def route(destination: str, target_type: str, target: str) -> dict:
    return {
        "destination": destination,
        "target_type": target_type,
        "target": target,
        "state": "active",
    }


def endpoint_for(snapshot: dict, service: str) -> dict:
    return next(row for row in snapshot["endpoints"] if row["service"] == service)


def subnets_in_tier(snapshot: dict, tier: str) -> list[dict]:
    return [row for row in snapshot["subnets"] if row["tier"] == tier]


def native_alarm_for(snapshot: dict, suffix: str) -> dict:
    matches = [
        alarm
        for alarm in snapshot["native_alarms"]["metric_alarms"]
        if str(alarm.get("name", "")).endswith(suffix)
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one native alarm ending {suffix!r}")
    return matches[0]


NATIVE_LB_ARN = (
    "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
    "loadbalancer/net/layerv-nhp-sandbox-relay-nhp/def123"
)
NATIVE_TG_ARN = (
    "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
    "targetgroup/rlyudp-native/abc123"
)
NATIVE_LB_DNS = "layerv-nhp-sandbox-relay-nhp-def123.elb.us-east-2.amazonaws.com"
NATIVE_LB_ZONE_ID = "ZLMOA37VPKANP"
NATIVE_ALARM_ACTION_ARN = (
    "arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"
)
RECORDED_NATIVE_LB_ARN = (
    "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
    "loadbalancer/net/relay-nhp/def456"
)
RECORDED_NATIVE_TG_ARN = (
    "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
    "targetgroup/rlyudp-recorded/789abc"
)
RECORDED_NATIVE_LB_DNS = "relay-nhp-def456.elb.us-east-2.amazonaws.com"


def good_snapshot() -> dict:
    region = "us-east-2"
    dmz_vpc = "vpc-dmz"
    main_vpc = "vpc-main"
    peer = "pcx-main"
    relay_sg = "sg-relay"
    alb_sg = "sg-alb"
    native_nhp_sg = "sg-native-nhp"
    endpoint_sg = "sg-endpoint"
    server_sg = "sg-server"
    relay_cidrs = ["10.101.10.0/24", "10.101.11.0/24", "10.101.12.0/24"]
    main_cidrs = ["10.100.10.0/24", "10.100.11.0/24", "10.100.12.0/24"]
    local_route = route("10.101.0.0/16", "gateway", "local")
    subnets = []
    for index in range(3):
        subnets.append(
            {
                "id": f"subnet-public-{index}",
                "vpc_id": dmz_vpc,
                "cidr": f"10.101.{index}.0/24",
                "availability_zone": f"us-east-2{'abc'[index]}",
                "map_public_ip_on_launch": False,
                "tier": "public-alb",
                "route_table_id": "rtb-public",
                "routes": [
                    local_route,
                    route("0.0.0.0/0", "gateway", "igw-dmz"),
                ],
            }
        )
        subnets.append(
            {
                "id": f"subnet-relay-{index}",
                "vpc_id": dmz_vpc,
                "cidr": relay_cidrs[index],
                "availability_zone": f"us-east-2{'abc'[index]}",
                "map_public_ip_on_launch": False,
                "tier": "isolated-relay",
                "route_table_id": f"rtb-relay-{index}",
                "routes": [
                    local_route,
                    *(route(cidr, "peering", peer) for cidr in main_cidrs),
                    route("pl-s3", "gateway", "vpce-s3"),
                ],
            }
        )
        subnets.append(
            {
                "id": f"subnet-endpoint-{index}",
                "vpc_id": dmz_vpc,
                "cidr": f"10.101.{20 + index}.0/24",
                "availability_zone": f"us-east-2{'abc'[index]}",
                "map_public_ip_on_launch": False,
                "tier": "isolated-endpoint",
                "route_table_id": f"rtb-endpoint-{index}",
                "routes": [local_route],
            }
        )

    instances = [
        {
            "id": f"i-relay-{index}",
            "state": "running",
            "vpc_id": dmz_vpc,
            "subnet_id": f"subnet-relay-{index}",
            "private_ip": f"10.101.{10 + index}.10",
            "public_ip": None,
            "ipv6": [],
            "security_group_ids": [relay_sg],
        }
        for index in range(3)
    ]

    endpoint_services = [
        "ecr.api",
        "ecr.dkr",
        "guardduty-data",
        "logs",
        "monitoring",
        "secretsmanager",
        "ssm",
        "ssmmessages",
    ]
    endpoints = [
        {
            "id": f"vpce-{service.replace('.', '-')}",
            "service": service,
            "type": "Interface",
            "state": "available",
            "private_dns_enabled": True,
            "subnet_ids": [f"subnet-endpoint-{index}" for index in range(3)],
            "route_table_ids": [],
            "security_group_ids": [endpoint_sg],
            "policy": endpoint_policy(service),
        }
        for service in endpoint_services
    ]
    endpoints.append(
        {
            "id": "vpce-s3",
            "service": "s3",
            "type": "Gateway",
            "state": "available",
            "private_dns_enabled": False,
            "subnet_ids": [],
            "route_table_ids": [f"rtb-relay-{index}" for index in range(3)],
            "security_group_ids": [],
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": sorted(checker._expected_s3_resources(region)),
                    }
                ],
            },
        }
    )

    relay_outbound = [
        *(rule("udp", 62206, 62206, "cidr_ipv4", cidr) for cidr in main_cidrs),
        rule("tcp", 443, 443, "security_group", endpoint_sg),
        rule("tcp", 443, 443, "prefix_list", "pl-s3"),
    ]
    by_id = {
        relay_sg: {
            "id": relay_sg,
            "vpc_id": dmz_vpc,
            "inbound": [
                rule("tcp", 8080, 8080, "security_group", alb_sg),
                rule("udp", 62207, 62207, "security_group", server_sg),
                rule("udp", 62206, 62206, "security_group", native_nhp_sg),
                rule("tcp", 8080, 8080, "security_group", native_nhp_sg),
            ],
            "outbound": relay_outbound,
        },
        alb_sg: {
            "id": alb_sg,
            "vpc_id": dmz_vpc,
            "inbound": [rule("tcp", 443, 443, "cidr_ipv4", "0.0.0.0/0")],
            "outbound": [rule("tcp", 8080, 8080, "security_group", relay_sg)],
        },
        native_nhp_sg: {
            "id": native_nhp_sg,
            "vpc_id": dmz_vpc,
            "inbound": [rule("udp", 62206, 62206, "cidr_ipv4", "0.0.0.0/0")],
            "outbound": [
                rule("udp", 62206, 62206, "security_group", relay_sg),
                rule("tcp", 8080, 8080, "security_group", relay_sg),
            ],
        },
        endpoint_sg: {
            "id": endpoint_sg,
            "vpc_id": dmz_vpc,
            "inbound": [rule("tcp", 443, 443, "security_group", relay_sg)],
            "outbound": [],
        },
        server_sg: {
            "id": server_sg,
            "vpc_id": main_vpc,
            "inbound": [
                rule("udp", 62206, 62206, "cidr_ipv4", "10.100.0.0/16"),
                *(rule("udp", 62206, 62206, "cidr_ipv4", cidr) for cidr in relay_cidrs),
            ],
            "outbound": [],
        },
    }

    dns_rules = [
        {
            "action": "BLOCK",
            "priority": priority,
            "dns_threat_protection": protection,
            "confidence_threshold": "HIGH",
            "block_response": "NODATA",
            "redirection_action": None,
            "domains": [],
        }
        for protection, priority in (
            ("DGA", 100),
            ("DICTIONARY_DGA", 110),
            ("DNS_TUNNELING", 120),
        )
    ]
    dns_rules.extend(
        [
            {
                "action": "ALLOW",
                "priority": 200,
                "dns_threat_protection": None,
                "confidence_threshold": None,
                "block_response": None,
                "redirection_action": "TRUST_REDIRECTION_DOMAIN",
                "domains": sorted(checker._expected_dns_domains(region)),
            },
            {
                "action": "BLOCK",
                "priority": 900,
                "dns_threat_protection": None,
                "confidence_threshold": None,
                "block_response": "NODATA",
                "redirection_action": None,
                "domains": ["*"],
            },
        ]
    )

    instance_ids = [row["id"] for row in instances]
    return {
        "schema_version": checker.SCHEMA_VERSION,
        "environment": "sandbox",
        "region": region,
        "account_id": "767397897469",
        "canonical_asg": {
            "name": "layerv-nhp-sandbox-relay-dmz",
            "vpc_id": dmz_vpc,
            "subnet_ids": [f"subnet-relay-{index}" for index in range(3)],
            "instance_ids": instance_ids,
            "members": [
                {
                    "instance_id": instance_id,
                    "lifecycle_state": "InService",
                    "health_status": "Healthy",
                }
                for instance_id in instance_ids
            ],
            "min_size": 3,
            "desired_capacity": 3,
            "target_group_arns": ["tg-arn", NATIVE_TG_ARN],
        },
        "orphaned_legacy_resources": {
            "asgs": [],
            "main_vpc_security_groups": [],
            "public_main_vpc_nhp_listeners": [],
            "target_groups": [],
        },
        "vpc": {
            "id": dmz_vpc,
            "cidr": "10.101.0.0/16",
            "ipv4_cidr_associations": [
                {"cidr": "10.101.0.0/16", "state": "associated"}
            ],
            "ipv6_cidr_associations": [],
        },
        "peer": {
            "id": peer,
            "active_peer_count": 1,
            "main_vpc_id": main_vpc,
            "main_vpc_cidr": "10.100.0.0/16",
            "dmz_dns_resolution": True,
            "main_dns_resolution": True,
        },
        "subnets": subnets,
        "main_private_routes": [
            {
                "subnet_id": f"subnet-main-private-{index}",
                "cidr": main_cidrs[index],
                "route_table_id": "rtb-main-private",
                "route_table_tags": {
                    "Name": "layerv-nhp-sandbox-rtb-private-extensible-0",
                    "Component": "networking",
                },
                "routes": [
                    route("10.100.0.0/16", "gateway", "local"),
                    *(route(cidr, "peering", peer) for cidr in relay_cidrs),
                    route("0.0.0.0/0", "nat", "nat-main"),
                ],
            }
            for index in range(3)
        ],
        "instances": instances,
        "relay_network_interfaces": [
            {
                "id": f"eni-relay-{index}",
                "subnet_id": f"subnet-relay-{index}",
                "private_ip": f"10.101.{10 + index}.10",
                "public_ip": None,
                "ipv6": [],
                "security_group_ids": [relay_sg],
                "status": "in-use",
            }
            for index in range(3)
        ],
        "security_groups": {
            "relay_ids": [relay_sg],
            "endpoint_ids": [endpoint_sg],
            "alb_ids": [alb_sg],
            "native_nhp_ids": [native_nhp_sg],
            "server_ids": [server_sg],
            "by_id": by_id,
        },
        "endpoints": endpoints,
        "flow_logs": [
            {
                "id": "fl-dmz",
                "traffic_type": "ALL",
                "flow_log_status": "ACTIVE",
                "delivery_status": "SUCCESS",
                "destination_type": "cloud-watch-logs",
                "destination_arn": "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/flow",
                "max_aggregation_interval": 60,
                "log_format": checker.EXPECTED_FLOW_LOG_FORMAT,
            }
        ],
        "security_log_groups": {
            "flow": {
                "name": "/layerv/nhp/sandbox/relay-dmz/flow",
                "arn": "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/flow",
                "kms_key_id": "arn:aws:kms:us-east-2:767397897469:key/logs-key",
                "retention_in_days": 30,
            },
            "resolver": {
                "name": "/layerv/nhp/sandbox/relay-dmz/resolver",
                "arn": "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/resolver",
                "kms_key_id": "arn:aws:kms:us-east-2:767397897469:key/logs-key",
                "retention_in_days": 30,
            },
        },
        "logs_kms_policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableAccountAdministration",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::767397897469:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowCloudWatchLogs",
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.us-east-2.amazonaws.com"},
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:DescribeKey",
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:CallerAccount": "767397897469",
                            "kms:ViaService": "logs.us-east-2.amazonaws.com",
                        },
                        "ArnEquals": {
                            "kms:EncryptionContext:aws:logs:arn": [
                                "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/flow",
                                "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/resolver",
                            ]
                        },
                    },
                },
            ],
        },
        "resolver": {
            "firewall_fail_open": "DISABLED",
            "firewall_associations": [
                {
                    "id": "rslvr-frgassoc-dmz",
                    "status": "COMPLETE",
                    "mutation_protection": "DISABLED",
                    "priority": 100,
                    "rules": dns_rules,
                }
            ],
            "query_log_configs": [
                {
                    "association_status": "CREATED",
                    "status": "CREATED",
                    "destination_arn": "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/resolver",
                    "name": "layerv-nhp-sandbox-relay-dmz",
                }
            ],
        },
        "alb": {
            "arn": "arn:aws:elasticloadbalancing:us-east-2:767397897469:loadbalancer/app/layerv-nhp-sandbox-relay/abc",
            "name": "layerv-nhp-sandbox-relay",
            "vpc_id": dmz_vpc,
            "scheme": "internet-facing",
            "type": "application",
            "tags": {
                "Environment": "sandbox",
                "Service": "nhp-relay",
                "Component": "relay",
                "Name": "layerv-nhp-sandbox-relay",
            },
            "deletion_protection_enabled": "false",
            "idle_timeout_seconds": "30",
            "drop_invalid_headers_enabled": "true",
            "desync_mitigation_mode": "defensive",
            "xff_header_processing_mode": "append",
            "xff_client_port_enabled": "false",
            "waf_fail_open_enabled": "false",
            "access_logs_enabled": "true",
            "access_logs_bucket": "layerv-nhp-sandbox-relay-alb-logs-767397897469",
            "access_logs_prefix": "",
            "security_group_ids": [alb_sg],
            "listeners": [
                {
                    "arn": "listener-arn",
                    "port": 443,
                    "protocol": "HTTPS",
                    "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                    "rules": [
                        {
                            "is_default": True,
                            "priority": "default",
                            "conditions": [],
                            "actions": [{"Type": "fixed-response"}],
                        },
                        {
                            "is_default": False,
                            "priority": "100",
                            "conditions": [
                                {"Field": "path-pattern", "Values": ["/relay/*"]},
                                {
                                    "Field": "http-request-method",
                                    "Values": ["POST", "OPTIONS"],
                                },
                            ],
                            "actions": [
                                {"Type": "forward", "TargetGroupArn": "tg-arn"}
                            ],
                        },
                    ],
                }
            ],
            "target_group_arns": ["tg-arn"],
            "target_groups": [
                {
                    "arn": "tg-arn",
                    "vpc_id": dmz_vpc,
                    "protocol": "HTTPS",
                    "port": 8080,
                    "target_type": "instance",
                    "health_check_enabled": True,
                    "health_check_protocol": "HTTPS",
                    "health_check_port": "traffic-port",
                    "health_check_path": "/health/live",
                    "health_check_matcher": "200",
                    "healthy_threshold": 2,
                    "unhealthy_threshold": 2,
                    "health_check_interval": 15,
                    "health_check_timeout": 5,
                }
            ],
            "waf_arn": "arn:aws:wafv2:us-east-2:767397897469:regional/webacl/relay/abc",
        },
        "native_nlb": {
            "arn": NATIVE_LB_ARN,
            "name": "layerv-nhp-sandbox-relay-nhp",
            "dns_name": NATIVE_LB_DNS,
            "canonical_hosted_zone_id": NATIVE_LB_ZONE_ID,
            "vpc_id": dmz_vpc,
            "scheme": "internet-facing",
            "type": "network",
            "ip_address_type": "ipv4",
            "subnet_ids": [f"subnet-public-{index}" for index in range(3)],
            "cross_zone_enabled": "true",
            "deletion_protection_enabled": "false",
            "tags": {
                "Environment": "sandbox",
                "Service": "nhp-relay",
                "Component": "relay",
                "Name": "layerv-nhp-sandbox-relay-nhp",
            },
            "security_group_ids": [native_nhp_sg],
            "listeners": [
                {
                    "arn": "native-listener-arn",
                    "port": 62206,
                    "protocol": "UDP",
                    "actions": [{"Type": "forward", "TargetGroupArn": NATIVE_TG_ARN}],
                }
            ],
            "target_group_arns": [NATIVE_TG_ARN],
            "target_groups": [
                {
                    "arn": NATIVE_TG_ARN,
                    "vpc_id": dmz_vpc,
                    "protocol": "UDP",
                    "port": 62206,
                    "target_type": "instance",
                    "preserve_client_ip": "true",
                    "health_check_enabled": True,
                    "health_check_protocol": "HTTPS",
                    "health_check_port": "8080",
                    "health_check_path": "/health/native-ready",
                    "health_check_matcher": "200",
                    "healthy_threshold": 2,
                    "unhealthy_threshold": 2,
                    "health_check_interval": 15,
                    "health_check_timeout": 5,
                }
            ],
        },
        "native_dns": {
            "record_count": 1,
            "hosted_zone_id": "Z10394893FM38A1RXLL32",
            "name": "native.nhp.layerv.xyz",
            "type": "A",
            "alias_dns_name": NATIVE_LB_DNS,
            "alias_hosted_zone_id": NATIVE_LB_ZONE_ID,
            "evaluate_target_health": True,
            "set_identifier": None,
            "weight": None,
            "region": None,
            "failover": None,
            "multi_value_answer": False,
            "health_check_id": None,
            "traffic_policy_instance_id": None,
            "ttl": None,
            "resource_record_count": 0,
        },
        "native_alarms": {
            "metric_alarms": [
                {
                    "name": "layerv-nhp-sandbox-relay-native-nlb-unhealthy",
                    "state_value": "OK",
                    "state_reason": "Threshold Crossed: no unhealthy targets",
                    "actions_enabled": True,
                    "alarm_actions": [NATIVE_ALARM_ACTION_ARN],
                    "ok_actions": [NATIVE_ALARM_ACTION_ARN],
                    "insufficient_data_actions": [],
                    "comparison_operator": "GreaterThanThreshold",
                    "evaluation_periods": 2,
                    "datapoints_to_alarm": 2,
                    "metric_name": "UnHealthyHostCount",
                    "namespace": "AWS/NetworkELB",
                    "period": 60,
                    "statistic": "Maximum",
                    "unit": None,
                    "threshold": 0,
                    "treat_missing_data": "notBreaching",
                    "dimension_count": 2,
                    "metric_query_count": 0,
                    "dimensions": {
                        "LoadBalancer": "net/layerv-nhp-sandbox-relay-nhp/def123",
                        "TargetGroup": "targetgroup/rlyudp-native/abc123",
                    },
                },
                {
                    "name": "layerv-nhp-sandbox-relay-native-nlb-zero-healthy",
                    "state_value": "OK",
                    "state_reason": "Threshold Crossed: healthy targets present",
                    "actions_enabled": True,
                    "alarm_actions": [NATIVE_ALARM_ACTION_ARN],
                    "ok_actions": [NATIVE_ALARM_ACTION_ARN],
                    "insufficient_data_actions": [],
                    "comparison_operator": "LessThanThreshold",
                    "evaluation_periods": 2,
                    "datapoints_to_alarm": 2,
                    "metric_name": "HealthyHostCount",
                    "namespace": "AWS/NetworkELB",
                    "period": 60,
                    "statistic": "Minimum",
                    "unit": None,
                    "threshold": 1,
                    "treat_missing_data": "breaching",
                    "dimension_count": 2,
                    "metric_query_count": 0,
                    "dimensions": {
                        "LoadBalancer": "net/layerv-nhp-sandbox-relay-nhp/def123",
                        "TargetGroup": "targetgroup/rlyudp-native/abc123",
                    },
                },
            ],
            "composite_alarm_names": [],
        },
        "functional": {
            "target_health": [
                {
                    "instance_id": instance_id,
                    "state": "healthy",
                    "reason": None,
                    "target_group_arn": target_group_arn,
                }
                for target_group_arn in ("tg-arn", NATIVE_TG_ARN)
                for instance_id in instance_ids
            ],
            "ssm": [
                {
                    "instance_id": instance_id,
                    "ping_status": "Online",
                    "agent_version": "3.3.4121.0",
                    "platform": "Ubuntu",
                }
                for instance_id in instance_ids
            ],
            "guardduty_detector_count": 1,
            "guardduty_coverage": [
                {
                    "instance_id": instance_id,
                    "status": "HEALTHY",
                    "issue": "",
                    "agent_version": "v1.15.0",
                    "management_type": "AUTO_MANAGED",
                }
                for instance_id in instance_ids
            ],
            "probes": [
                {
                    "instance_id": instance_id,
                    "status": "Success",
                    "allowed_dns": True,
                    "blocked_public_dns": True,
                    "public_tcp_unreachable": True,
                    "relay_active": True,
                }
                for instance_id in instance_ids
            ],
        },
    }


def good_prod_snapshot() -> dict:
    snapshot = json.loads(json.dumps(good_snapshot()).replace("sandbox", "prod"))
    snapshot["alb"]["deletion_protection_enabled"] = "true"
    snapshot["native_nlb"]["deletion_protection_enabled"] = "true"
    snapshot["native_dns"]["name"] = "native.nhp.layerv.ai"
    snapshot["native_dns"]["hosted_zone_id"] = "Z0748438C8EK6UAW94ST"
    for log_group in snapshot["security_log_groups"].values():
        log_group["retention_in_days"] = 365
    for index, row in enumerate(snapshot["main_private_routes"]):
        row["route_table_id"] = f"rtb-main-private-{index}"
        row["route_table_tags"]["Name"] = (
            f"layerv-nhp-prod-rtb-private-extensible-{index}"
        )
        for route_row in row["routes"]:
            if route_row.get("destination") == "0.0.0.0/0":
                route_row["target"] = f"nat-main-{index}"
    return snapshot


def functional_probe_aws(invocations: list[dict | Exception]) -> mock.Mock:
    invocation_results = iter(invocations)
    aws = mock.Mock()

    def call(service: str, operation: str, *args: str) -> dict:
        if (service, operation) == ("elbv2", "describe-target-health"):
            return {"TargetHealthDescriptions": []}
        if (service, operation) == ("ssm", "describe-instance-information"):
            return {"InstanceInformationList": []}
        if (service, operation) == ("guardduty", "list-detectors"):
            return {"DetectorIds": []}
        if (service, operation) == ("ssm", "describe-document"):
            return run_shell_document_description()
        if (service, operation) == ("ssm", "send-command"):
            timeout_index = args.index("--timeout-seconds")
            if args[timeout_index + 1] != str(checker.SSM_COMMAND_TIMEOUT_SECONDS):
                raise AssertionError("send-command did not use the named timeout")
            return {"Command": {"CommandId": "command-poll"}}
        if (service, operation) == ("ssm", "get-command-invocation"):
            result = next(invocation_results)
            if isinstance(result, Exception):
                raise result
            return result
        raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")

    aws.call.side_effect = call
    return aws


def run_shell_document_description(**overrides: str) -> dict:
    document = {
        "Name": checker.SSM_RUN_SHELL_DOCUMENT_NAME,
        "Owner": checker.SSM_RUN_SHELL_DOCUMENT_OWNER,
        "DocumentType": "Command",
        "Status": "Active",
        "HashType": "Sha256",
        "DocumentVersion": "1",
        "Hash": "a" * 64,
    }
    document.update(overrides)
    return {"Document": document}


class RecordedStructuralAws:
    """Recorded-shape AWS CLI fixture for collect_structural assembly tests."""

    region = "us-east-2"

    def __init__(
        self,
        *,
        dmz_is_requester: bool,
        empty_main_vpc: bool = False,
        empty_dmz_vpc: bool = False,
        empty_dmz_sg_ids: bool = False,
        extra_untagged_lb_reuses_alb_sg: bool = False,
        missing_main_peer_vpc_id: bool = False,
        public_main_vpc_nhp_protocol: str | None = None,
        public_main_vpc_nhp_name: str = "layerv-nhp-sandbox-nlb",
        waf_absent: bool = False,
    ):
        self.dmz_is_requester = dmz_is_requester
        self.empty_main_vpc = empty_main_vpc
        self.empty_dmz_vpc = empty_dmz_vpc
        self.empty_dmz_sg_ids = empty_dmz_sg_ids
        self.extra_untagged_lb_reuses_alb_sg = extra_untagged_lb_reuses_alb_sg
        self.missing_main_peer_vpc_id = missing_main_peer_vpc_id
        self.public_main_vpc_nhp_protocol = public_main_vpc_nhp_protocol
        self.public_main_vpc_nhp_name = public_main_vpc_nhp_name
        self.waf_absent = waf_absent
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []

    def call(self, service: str, operation: str, *args: str) -> dict:
        self.calls.append((service, operation, args))
        dmz_vpc = "vpc-dmz-recorded"
        main_vpc = "vpc-main-recorded"
        peer_id = "pcx-recorded"
        flow_log_group = (
            "arn:aws:logs:us-east-2:767397897469:"
            "log-group:/layerv/nhp/sandbox/relay-dmz/flow"
        )
        resolver_log_group = (
            "arn:aws:logs:us-east-2:767397897469:"
            "log-group:/layerv/nhp/sandbox/relay-dmz/resolver"
        )

        if (service, operation) == ("ssm", "get-parameter"):
            return {"Parameter": {"Value": "layerv-nhp-sandbox-relay-dmz"}}
        if (service, operation) == (
            "autoscaling",
            "describe-auto-scaling-groups",
        ):
            return {
                "AutoScalingGroups": [
                    {
                        "AutoScalingGroupName": "layerv-nhp-sandbox-relay-dmz",
                        "VPCZoneIdentifier": "subnet-relay-recorded",
                        "MinSize": 1,
                        "DesiredCapacity": 1,
                        "TargetGroupARNs": ["tg-recorded", RECORDED_NATIVE_TG_ARN],
                        "Instances": [
                            {
                                "InstanceId": "i-relay-recorded",
                                "LifecycleState": "InService",
                                "HealthStatus": "Healthy",
                            }
                        ],
                        "Tags": [
                            {"Key": "Service", "Value": "nhp-relay"},
                            {"Key": "Environment", "Value": "sandbox"},
                        ],
                    }
                ]
            }
        if (service, operation) == ("ec2", "describe-subnets"):
            if "--subnet-ids" in args:
                return {
                    "Subnets": [
                        {
                            "SubnetId": "subnet-relay-recorded",
                            "VpcId": dmz_vpc,
                            "CidrBlock": "10.101.10.0/24",
                            "AvailabilityZone": "us-east-2a",
                            "MapPublicIpOnLaunch": False,
                            "Tags": [{"Key": "Tier", "Value": "isolated-relay"}],
                        }
                    ]
                }
            if f"Name=vpc-id,Values={main_vpc}" in args:
                return {
                    "Subnets": [
                        {
                            "SubnetId": "subnet-main-recorded",
                            "VpcId": main_vpc,
                            "CidrBlock": "10.100.10.0/24",
                            "Tags": [{"Key": "Type", "Value": "private"}],
                        }
                    ]
                }
            return {
                "Subnets": [
                    {
                        "SubnetId": "subnet-relay-recorded",
                        "VpcId": dmz_vpc,
                        "CidrBlock": "10.101.10.0/24",
                        "AvailabilityZone": "us-east-2a",
                        "MapPublicIpOnLaunch": False,
                        "Tags": [{"Key": "Tier", "Value": "isolated-relay"}],
                    }
                ]
            }
        if (service, operation) == ("ec2", "describe-route-tables"):
            if f"Name=vpc-id,Values={main_vpc}" in args:
                return {
                    "RouteTables": [
                        {
                            "RouteTableId": "rtb-main-recorded",
                            "Associations": [
                                {"SubnetId": "subnet-main-recorded", "Main": False}
                            ],
                            "Routes": [
                                {
                                    "DestinationCidrBlock": "10.100.0.0/16",
                                    "GatewayId": "local",
                                    "State": "active",
                                },
                                {
                                    "DestinationCidrBlock": "10.101.10.0/24",
                                    "VpcPeeringConnectionId": peer_id,
                                    "State": "active",
                                },
                            ],
                        }
                    ]
                }
            return {
                "RouteTables": [
                    {
                        "RouteTableId": "rtb-relay-recorded",
                        "Associations": [
                            {"SubnetId": "subnet-relay-recorded", "Main": False}
                        ],
                        "Routes": [
                            {
                                "DestinationCidrBlock": "10.101.0.0/16",
                                "GatewayId": "local",
                                "State": "active",
                            },
                            {
                                "DestinationCidrBlock": "10.100.10.0/24",
                                "VpcPeeringConnectionId": peer_id,
                                "State": "active",
                            },
                        ],
                    }
                ]
            }
        if (service, operation) == ("ec2", "describe-instances"):
            return {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-relay-recorded",
                                "State": {"Name": "running"},
                                "VpcId": dmz_vpc,
                                "SubnetId": "subnet-relay-recorded",
                                "PrivateIpAddress": "10.101.10.10",
                                "SecurityGroups": []
                                if self.empty_dmz_sg_ids
                                else [{"GroupId": "sg-relay-recorded"}],
                                "NetworkInterfaces": [
                                    {"Ipv6Addresses": [{"Ipv6Address": "2001:db8::10"}]}
                                ],
                            }
                        ]
                    }
                ]
            }
        if (service, operation) == ("ec2", "describe-vpc-endpoints"):
            return {
                "VpcEndpoints": [
                    {
                        "VpcEndpointId": "vpce-recorded",
                        "ServiceName": "com.amazonaws.us-east-2.logs",
                        "VpcEndpointType": "Interface",
                        "State": "available",
                        "PrivateDnsEnabled": True,
                        "SubnetIds": ["subnet-endpoint-recorded"],
                        "Groups": []
                        if self.empty_dmz_sg_ids
                        else [{"GroupId": "sg-endpoint-recorded"}],
                        "PolicyDocument": json.dumps({"Statement": []}),
                    }
                ]
            }
        if (service, operation) == ("elbv2", "describe-load-balancers"):
            return {
                "LoadBalancers": [
                    {
                        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-2:767397897469:loadbalancer/app/relay/1",
                        "LoadBalancerName": "layerv-nhp-sandbox-relay",
                        "VpcId": dmz_vpc,
                        "Type": "application",
                        "Scheme": "internet-facing",
                        "SecurityGroups": []
                        if self.empty_dmz_sg_ids
                        else ["sg-alb-recorded"],
                    },
                    {
                        "LoadBalancerArn": RECORDED_NATIVE_LB_ARN,
                        "LoadBalancerName": "layerv-nhp-sandbox-relay-nhp",
                        "DNSName": RECORDED_NATIVE_LB_DNS,
                        "CanonicalHostedZoneId": NATIVE_LB_ZONE_ID,
                        "VpcId": dmz_vpc,
                        "Type": "network",
                        "Scheme": "internet-facing",
                        "IpAddressType": "ipv4",
                        "AvailabilityZones": [{"SubnetId": "subnet-public-recorded"}],
                        "SecurityGroups": []
                        if self.empty_dmz_sg_ids
                        else ["sg-native-nhp-recorded"],
                    },
                    *(
                        [
                            {
                                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-2:767397897469:loadbalancer/net/public-main-nhp/legacy",
                                "LoadBalancerName": self.public_main_vpc_nhp_name,
                                "VpcId": main_vpc,
                                "Type": "network",
                                "Scheme": "internet-facing",
                            }
                        ]
                        if self.public_main_vpc_nhp_protocol is not None
                        else []
                    ),
                    *(
                        [
                            {
                                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-2:767397897469:loadbalancer/app/rogue/2",
                                "LoadBalancerName": "rogue-untagged",
                                "VpcId": dmz_vpc,
                                "Type": "application",
                                "Scheme": "internet-facing",
                                "SecurityGroups": ["sg-alb-recorded"],
                            }
                        ]
                        if self.extra_untagged_lb_reuses_alb_sg
                        else []
                    ),
                ]
            }
        if (service, operation) == (
            "elbv2",
            "describe-load-balancer-attributes",
        ):
            load_balancer_arn = args[args.index("--load-balancer-arn") + 1]
            if "/app/" in load_balancer_arn:
                return {
                    "Attributes": [
                        {"Key": "deletion_protection.enabled", "Value": "false"},
                        {"Key": "idle_timeout.timeout_seconds", "Value": "30"},
                        {
                            "Key": "routing.http.drop_invalid_header_fields.enabled",
                            "Value": "true",
                        },
                        {
                            "Key": "routing.http.desync_mitigation_mode",
                            "Value": "defensive",
                        },
                        {
                            "Key": "routing.http.xff_header_processing.mode",
                            "Value": "append",
                        },
                        {
                            "Key": "routing.http.xff_client_port.enabled",
                            "Value": "false",
                        },
                        {"Key": "waf.fail_open.enabled", "Value": "false"},
                        {"Key": "access_logs.s3.enabled", "Value": "true"},
                        {
                            "Key": "access_logs.s3.bucket",
                            "Value": "layerv-nhp-sandbox-relay-alb-logs-767397897469",
                        },
                        {"Key": "access_logs.s3.prefix", "Value": ""},
                    ]
                }
            return {
                "Attributes": [
                    {"Key": "load_balancing.cross_zone.enabled", "Value": "true"},
                    {"Key": "deletion_protection.enabled", "Value": "false"},
                ]
            }
        if (service, operation) == ("elbv2", "describe-tags"):
            return {
                "TagDescriptions": [
                    {
                        "ResourceArn": arn,
                        "Tags": []
                        if "/rogue/" in arn
                        else [
                            {"Key": "Environment", "Value": "sandbox"},
                            {"Key": "Service", "Value": "nhp-relay"},
                            {"Key": "Component", "Value": "relay"},
                            {
                                "Key": "Name",
                                "Value": "layerv-nhp-sandbox-relay-nhp"
                                if "/net/" in arn
                                else "layerv-nhp-sandbox-relay",
                            },
                        ],
                    }
                    for arn in args[1:]
                ]
            }
        if (service, operation) == ("ec2", "describe-security-groups"):
            if "--group-ids" not in args:
                return {"SecurityGroups": [{"GroupId": "sg-legacy-recorded"}]}
            return {
                "SecurityGroups": [
                    {
                        "GroupId": group_id,
                        "VpcId": dmz_vpc,
                        "GroupName": group_id,
                        "IpPermissions": [],
                        "IpPermissionsEgress": [],
                    }
                    for group_id in (
                        "sg-relay-recorded",
                        "sg-endpoint-recorded",
                        "sg-alb-recorded",
                        "sg-native-nhp-recorded",
                    )
                    if group_id in args
                ]
            }
        if (service, operation) == ("ec2", "describe-vpc-peering-connections"):
            dmz_info = {
                "VpcId": dmz_vpc,
                "PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": True},
            }
            main_info = {
                "VpcId": main_vpc,
                "PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": False},
            }
            if self.missing_main_peer_vpc_id:
                main_info.pop("VpcId")
            peer = {
                "VpcPeeringConnectionId": peer_id,
                "Status": {"Code": "active"},
                "RequesterVpcInfo": dmz_info if self.dmz_is_requester else main_info,
                "AccepterVpcInfo": main_info if self.dmz_is_requester else dmz_info,
            }
            requester_filter = f"Name=requester-vpc-info.vpc-id,Values={dmz_vpc}"
            returns_peer = (requester_filter in args) == self.dmz_is_requester
            return {"VpcPeeringConnections": [peer] if returns_peer else []}
        if (service, operation) == ("ec2", "describe-vpcs"):
            vpc_id = args[-1]
            if vpc_id == main_vpc:
                if self.empty_main_vpc:
                    return {"Vpcs": []}
                return {"Vpcs": [{"VpcId": main_vpc, "CidrBlock": "10.100.0.0/16"}]}
            if self.empty_dmz_vpc:
                return {"Vpcs": []}
            return {
                "Vpcs": [
                    {
                        "VpcId": dmz_vpc,
                        "CidrBlock": "10.101.0.0/16",
                        "CidrBlockAssociationSet": [
                            {
                                "CidrBlock": "10.101.0.0/16",
                                "CidrBlockState": {"State": "associated"},
                            }
                        ],
                        "Ipv6CidrBlockAssociationSet": [],
                    }
                ]
            }
        if (service, operation) == ("ec2", "describe-network-interfaces"):
            return {
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-relay-recorded",
                        "SubnetId": "subnet-relay-recorded",
                        "PrivateIpAddress": "10.101.10.10",
                        "Groups": [{"GroupId": "sg-relay-recorded"}],
                        "Status": "in-use",
                    }
                ]
            }
        if (service, operation) == ("elbv2", "describe-listeners"):
            if any("/net/public-main-nhp/" in arg for arg in args):
                return {
                    "Listeners": [
                        {
                            "ListenerArn": "listener-public-main-nhp",
                            "Port": 62206,
                            "Protocol": self.public_main_vpc_nhp_protocol,
                        }
                    ]
                }
            if RECORDED_NATIVE_LB_ARN in args:
                return {
                    "Listeners": [
                        {
                            "ListenerArn": "native-listener-recorded",
                            "Port": 62206,
                            "Protocol": "UDP",
                            "DefaultActions": [
                                {
                                    "Type": "forward",
                                    "TargetGroupArn": RECORDED_NATIVE_TG_ARN,
                                }
                            ],
                        }
                    ]
                }
            return {
                "Listeners": [
                    {
                        "ListenerArn": "listener-recorded",
                        "Port": 443,
                        "Protocol": "HTTPS",
                        "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                    }
                ]
            }
        if (service, operation) == ("elbv2", "describe-rules"):
            return {
                "Rules": [
                    {
                        "IsDefault": False,
                        "Priority": "10",
                        "Conditions": [
                            {"Field": "path-pattern", "Values": ["/relay/*"]}
                        ],
                        "Actions": [
                            {
                                "Type": "forward",
                                "TargetGroupArn": "tg-recorded",
                            }
                        ],
                    }
                ]
            }
        if (service, operation) == ("elbv2", "describe-target-groups"):
            if "--target-group-arns" not in args:
                return {
                    "TargetGroups": [
                        {
                            "TargetGroupArn": "tg-old-recorded",
                            "TargetGroupName": "rlytls-old",
                            "VpcId": main_vpc,
                        },
                        {
                            "TargetGroupArn": "tg-recorded",
                            "TargetGroupName": "rlytls-current",
                            "VpcId": dmz_vpc,
                        },
                        {
                            "TargetGroupArn": RECORDED_NATIVE_TG_ARN,
                            "TargetGroupName": "rlyudp-current",
                            "VpcId": dmz_vpc,
                        },
                        {
                            "TargetGroupArn": "tg-dmz-orphan-recorded",
                            "TargetGroupName": "rlyudp-old",
                            "VpcId": dmz_vpc,
                        },
                    ]
                }
            if RECORDED_NATIVE_TG_ARN in args:
                return {
                    "TargetGroups": [
                        {
                            "TargetGroupArn": RECORDED_NATIVE_TG_ARN,
                            "VpcId": dmz_vpc,
                            "Protocol": "UDP",
                            "Port": 62206,
                            "TargetType": "instance",
                            "HealthCheckEnabled": True,
                            "HealthCheckProtocol": "HTTPS",
                            "HealthCheckPort": "8080",
                            "HealthCheckPath": "/health/native-ready",
                            "Matcher": {"HttpCode": "200"},
                            "HealthyThresholdCount": 2,
                            "UnhealthyThresholdCount": 2,
                            "HealthCheckIntervalSeconds": 15,
                            "HealthCheckTimeoutSeconds": 5,
                        }
                    ]
                }
            return {
                "TargetGroups": [
                    {
                        "TargetGroupArn": "tg-recorded",
                        "VpcId": dmz_vpc,
                        "Protocol": "HTTPS",
                        "Port": 8080,
                        "TargetType": "instance",
                        "HealthCheckEnabled": True,
                        "HealthCheckProtocol": "HTTPS",
                        "HealthCheckPort": "traffic-port",
                        "HealthCheckPath": "/health/live",
                        "Matcher": {"HttpCode": "200"},
                        "HealthyThresholdCount": 2,
                        "UnhealthyThresholdCount": 2,
                        "HealthCheckIntervalSeconds": 15,
                        "HealthCheckTimeoutSeconds": 5,
                    }
                ]
            }
        if (service, operation) == (
            "elbv2",
            "describe-target-group-attributes",
        ):
            return {
                "Attributes": [{"Key": "preserve_client_ip.enabled", "Value": "true"}]
            }
        if (service, operation) == ("wafv2", "get-web-acl-for-resource"):
            if self.waf_absent:
                raise checker.InventoryError(
                    "AWS CLI failed (wafv2 get-web-acl-for-resource): "
                    "WAFNonexistentItemException"
                )
            return {"WebACL": {"ARN": "waf-recorded"}}
        if (service, operation) == ("ec2", "describe-flow-logs"):
            return {
                "FlowLogs": [
                    {
                        "FlowLogId": "fl-recorded",
                        "TrafficType": "ALL",
                        "FlowLogStatus": "ACTIVE",
                        "DeliverLogsStatus": "SUCCESS",
                        "LogDestinationType": "cloud-watch-logs",
                        "LogDestination": flow_log_group,
                        "LogGroupName": "must-not-be-used-as-destination",
                        "MaxAggregationInterval": 60,
                        "LogFormat": "${pkt-srcaddr}",
                    }
                ]
            }
        if (service, operation) == ("logs", "describe-log-groups"):
            return {
                "logGroups": [
                    {
                        "logGroupName": "/layerv/nhp/sandbox/relay-dmz/flow",
                        "logGroupArn": flow_log_group,
                        "kmsKeyId": "kms-recorded",
                        "retentionInDays": 30,
                    },
                    {
                        "logGroupName": "/layerv/nhp/sandbox/relay-dmz/resolver",
                        "logGroupArn": resolver_log_group,
                        "kmsKeyId": "kms-recorded",
                        "retentionInDays": 30,
                    },
                ]
            }
        if (service, operation) == ("kms", "get-key-policy"):
            return {"Policy": json.dumps({"Version": "2012-10-17", "Statement": []})}
        if (
            service,
            operation,
        ) == ("route53resolver", "list-firewall-rule-group-associations"):
            return {
                "FirewallRuleGroupAssociations": [
                    {
                        "Id": "rslvr-assoc-recorded",
                        "Status": "COMPLETE",
                        "MutationProtection": "DISABLED",
                        "Priority": 100,
                        "FirewallRuleGroupId": "rslvr-group-recorded",
                    }
                ]
            }
        if (service, operation) == ("route53resolver", "list-firewall-rules"):
            return {
                "FirewallRules": [
                    {
                        "Action": "BLOCK",
                        "BlockResponse": "NODATA",
                        "Priority": 100,
                        "DnsThreatProtection": "DGA",
                        "ConfidenceThreshold": "HIGH",
                    },
                    {
                        "Action": "ALLOW",
                        "Priority": 200,
                        "FirewallDomainListId": "rslvr-list-recorded",
                        "FirewallDomainRedirectionAction": "TRUST_REDIRECTION_DOMAIN",
                    },
                    {
                        "Action": "BLOCK",
                        "BlockResponse": "NODATA",
                        "Priority": 900,
                        "FirewallDomainListId": "rslvr-list-all-recorded",
                    },
                ]
            }
        if (service, operation) == ("route53resolver", "list-firewall-domains"):
            return {
                "Domains": ["*"]
                if args[-1] == "rslvr-list-all-recorded"
                else ["logs.us-east-2.amazonaws.com"]
            }
        if (service, operation) == ("route53resolver", "get-firewall-config"):
            return {"FirewallConfig": {"FirewallFailOpen": "DISABLED"}}
        if (
            service,
            operation,
        ) == ("route53resolver", "list-resolver-query-log-config-associations"):
            return {
                "ResolverQueryLogConfigAssociations": [
                    {
                        "Status": "ACTIVE",
                        "ResolverQueryLogConfigId": "rqlc-recorded",
                    }
                ]
            }
        if (
            service,
            operation,
        ) == ("route53resolver", "get-resolver-query-log-config"):
            return {
                "ResolverQueryLogConfig": {
                    "Status": "CREATED",
                    "DestinationArn": resolver_log_group,
                    "Name": "relay-resolver-recorded",
                }
            }
        if (service, operation) == ("route53", "list-resource-record-sets"):
            return {
                "ResourceRecordSets": [
                    {
                        "Name": "native.nhp.layerv.xyz.",
                        "Type": "A",
                        "AliasTarget": {
                            "DNSName": f"{RECORDED_NATIVE_LB_DNS}.",
                            "HostedZoneId": NATIVE_LB_ZONE_ID,
                            "EvaluateTargetHealth": True,
                        },
                    }
                ]
            }
        if (service, operation) == ("cloudwatch", "describe-alarms"):
            dimensions = [
                {"Name": "LoadBalancer", "Value": "net/relay-nhp/def456"},
                {
                    "Name": "TargetGroup",
                    "Value": "targetgroup/rlyudp-recorded/789abc",
                },
            ]

            def alarm(name: str, *, zero_ready: bool) -> dict:
                return {
                    "AlarmName": name,
                    "StateValue": "OK",
                    "StateReason": "recorded fixture is healthy",
                    "ActionsEnabled": True,
                    "AlarmActions": [NATIVE_ALARM_ACTION_ARN],
                    "OKActions": [NATIVE_ALARM_ACTION_ARN],
                    "InsufficientDataActions": [],
                    "ComparisonOperator": (
                        "LessThanThreshold" if zero_ready else "GreaterThanThreshold"
                    ),
                    "EvaluationPeriods": 2,
                    "DatapointsToAlarm": 2,
                    "MetricName": (
                        "HealthyHostCount" if zero_ready else "UnHealthyHostCount"
                    ),
                    "Namespace": "AWS/NetworkELB",
                    "Period": 60,
                    "Statistic": "Minimum" if zero_ready else "Maximum",
                    "Unit": None,
                    "Threshold": 1 if zero_ready else 0,
                    "TreatMissingData": "breaching" if zero_ready else "notBreaching",
                    "Dimensions": dimensions,
                }

            return {
                "MetricAlarms": [
                    alarm(
                        "layerv-nhp-sandbox-relay-native-nlb-unhealthy",
                        zero_ready=False,
                    ),
                    alarm(
                        "layerv-nhp-sandbox-relay-native-nlb-zero-healthy",
                        zero_ready=True,
                    ),
                ],
                "CompositeAlarms": [],
            }
        if (service, operation) == ("sts", "get-caller-identity"):
            return {"Account": "767397897469"}
        raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")


class RelayDmzLiveCheckTests(unittest.TestCase):
    def test_wait_help_states_effective_wall_clock_bound(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit:
            checker._parse_args(["--help"])
        self.assertEqual(0, exit.exception.code)
        help_text = output.getvalue()
        self.assertIn("allowed to finish", help_text)
        self.assertIn("fresh functional confirmation", help_text)

    def test_embedded_public_tcp_probe_classification_is_fail_closed(self) -> None:
        for result, expected_exit in (
            (0, 1),
            (errno.ECONNREFUSED, 1),
            (errno.ETIMEDOUT, 0),
            (errno.EAGAIN, 0),
            (errno.ENETUNREACH, 0),
            (errno.EHOSTUNREACH, 0),
            (errno.EACCES, 2),
        ):
            fake_socket = mock.Mock()
            fake_socket.connect_ex.return_value = result
            with mock.patch("socket.socket", return_value=fake_socket):
                self.assertEqual(
                    expected_exit,
                    run_embedded_probe(checker.PUBLIC_TCP_PROBE_PY, "1.1.1.1", "443"),
                )
            fake_socket.close.assert_called_once_with()

    def test_embedded_negative_dns_probe_rejects_transients(self) -> None:
        with mock.patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror(socket.EAI_NONAME, "blocked"),
        ):
            self.assertEqual(0, run_embedded_probe(checker.NEGATIVE_DNS_PROBE_PY))
        with mock.patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror(socket.EAI_AGAIN, "temporary failure"),
        ):
            self.assertEqual(2, run_embedded_probe(checker.NEGATIVE_DNS_PROBE_PY))
        with mock.patch("socket.getaddrinfo", return_value=[]):
            self.assertEqual(1, run_embedded_probe(checker.NEGATIVE_DNS_PROBE_PY))

    def test_probe_output_format_and_parser_are_lockstep(self) -> None:
        output = checker.PROBE_OUTPUT_FORMAT % (1, 0, 1, 0)
        match = checker.PROBE_OUTPUT_RE.fullmatch(output)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(("1", "0", "1", "0"), match.groups())

        with self.assertRaisesRegex(ValueError, "exactly four"):
            checker._compile_probe_output_re("only-one=%s")

    def test_probe_cache_accepts_only_complete_success(self) -> None:
        success = {
            "status": "Success",
            "allowed_dns": True,
            "blocked_public_dns": True,
            "public_tcp_unreachable": True,
            "relay_active": True,
        }
        self.assertTrue(checker._probe_fully_successful(success))
        for field in success:
            with self.subTest(field=field):
                probe = dict(success)
                probe[field] = "Failed" if field == "status" else False
                self.assertFalse(checker._probe_fully_successful(probe))

    def test_service_suffix_keeps_multi_segment_endpoint_name(self) -> None:
        self.assertEqual(
            "ecr.api",
            checker._service_suffix("com.amazonaws.us-east-2.ecr.api"),
        )

    def test_aws_cli_region_resolution_is_explicit_and_fail_closed(self) -> None:
        with (
            mock.patch.dict(checker.os.environ, {}, clear=True),
            mock.patch.object(checker.subprocess, "run") as run,
        ):
            self.assertEqual("us-west-2", checker.AwsCli(" us-west-2 ").region)
            run.assert_not_called()

        with (
            mock.patch.dict(
                checker.os.environ, {"AWS_DEFAULT_REGION": "eu-west-1"}, clear=True
            ),
            mock.patch.object(checker.subprocess, "run") as run,
        ):
            self.assertEqual("eu-west-1", checker.AwsCli().region)
            run.assert_not_called()

        configured = mock.Mock(returncode=0, stdout="ap-southeast-2\n", stderr="")
        with (
            mock.patch.dict(checker.os.environ, {}, clear=True),
            mock.patch.object(checker.subprocess, "run", return_value=configured),
        ):
            self.assertEqual("ap-southeast-2", checker.AwsCli().region)

        for result in (
            mock.Mock(returncode=0, stdout="\n", stderr=""),
            mock.Mock(returncode=1, stdout="", stderr="profile not found\n"),
        ):
            with (
                self.subTest(returncode=result.returncode),
                mock.patch.dict(checker.os.environ, {}, clear=True),
                mock.patch.object(checker.subprocess, "run", return_value=result),
                self.assertRaisesRegex(
                    checker.InventoryError, "AWS region is not configured"
                ),
            ):
                checker.AwsCli()

        with (
            mock.patch.dict(checker.os.environ, {}, clear=True),
            mock.patch.object(
                checker.subprocess,
                "run",
                side_effect=FileNotFoundError("aws not installed"),
            ),
            self.assertRaisesRegex(
                checker.InventoryError, "AWS region is not configured"
            ),
        ):
            checker.AwsCli()

        for invalid_region in (
            "us-east-2; touch /tmp/pwned",
            "cn-north-1",
            "us-gov-west-1",
            "us-iso-east-1",
            "us-isob-east-1",
            "us-isof-south-1",
            "us-isoe-west-1",
            "eusc-de-east-1",
        ):
            with self.subTest(invalid_region=invalid_region):
                with self.assertRaisesRegex(
                    checker.InventoryError,
                    "not a valid commercial partition region",
                ):
                    checker.AwsCli(invalid_region)

    def test_commercial_region_allowlist_covers_reviewed_prefixes(self) -> None:
        for region in (
            "af-south-1",
            "ap-southeast-7",
            "ca-west-1",
            "eu-central-2",
            "il-central-1",
            "me-central-1",
            "mx-central-1",
            "sa-east-1",
            "us-east-2",
            "us-west-2",
        ):
            with self.subTest(region=region):
                self.assertEqual(region, checker._require_commercial_region(region))

    def test_environment_region_binding_is_exact(self) -> None:
        for environment in ("sandbox", "prod"):
            with self.subTest(environment=environment):
                checker._require_expected_environment_region(environment, "us-east-2")

        for environment, region, message in (
            ("sandbox", "us-west-2", "requires AWS region 'us-east-2'"),
            ("staging", "us-east-2", "no reviewed AWS region"),
        ):
            with (
                self.subTest(environment=environment, region=region),
                self.assertRaisesRegex(checker.InventoryError, message),
            ):
                checker._require_expected_environment_region(environment, region)

    def test_snapshot_region_binding_is_structural_and_functional(self) -> None:
        snapshot = good_snapshot()
        snapshot["region"] = "us-west-2"

        for mode, validate in (
            ("structural", checker.validate_structural),
            ("functional", checker.validate_functional),
        ):
            with self.subTest(mode=mode):
                errors = validate(copy.deepcopy(snapshot))
                self.assertTrue(
                    any(
                        "requires AWS region 'us-east-2', not 'us-west-2'" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_aws_cli_call_timeout_is_bounded_and_retryable(self) -> None:
        aws = checker.AwsCli("us-east-2")
        timeout = subprocess.TimeoutExpired(["aws", "ec2", "describe-vpcs"], 30)
        with mock.patch.object(checker.subprocess, "run", side_effect=timeout) as run:
            with self.assertRaisesRegex(
                checker.InventoryError, "AWS CLI timed out after 30s"
            ) as raised:
                aws.call("ec2", "describe-vpcs")

        self.assertTrue(checker._retryable_inventory_error(raised.exception))
        self.assertEqual(
            checker.AWS_CLI_TIMEOUT_SECONDS, run.call_args.kwargs["timeout"]
        )

    def test_aws_cli_call_preserves_default_auto_pagination(self) -> None:
        aws = checker.AwsCli("us-east-2")
        result = mock.Mock(returncode=0, stdout="{}", stderr="")
        with mock.patch.object(checker.subprocess, "run", return_value=result) as run:
            aws.call("elbv2", "describe-load-balancers")

        command = run.call_args.args[0]
        self.assertIn("--no-cli-pager", command)
        self.assertNotIn("--no-paginate", command)

    def test_aws_cli_call_rejects_error_and_invalid_output_shapes(self) -> None:
        aws = checker.AwsCli("us-east-2")
        cases = {
            "nonzero stderr": (
                mock.Mock(
                    returncode=2,
                    stdout="",
                    stderr="context line\nAccessDeniedException\n",
                ),
                "AWS CLI failed \\(ec2 describe-vpcs\\): AccessDeniedException",
            ),
            "invalid JSON": (
                mock.Mock(returncode=0, stdout="not-json", stderr=""),
                "AWS CLI returned invalid JSON \\(ec2 describe-vpcs\\)",
            ),
            "non-object JSON": (
                mock.Mock(returncode=0, stdout="[]", stderr=""),
                "AWS CLI returned a non-object \\(ec2 describe-vpcs\\)",
            ),
        }
        for name, (result, expected_error) in cases.items():
            with (
                self.subTest(name=name),
                mock.patch.object(checker.subprocess, "run", return_value=result),
                self.assertRaisesRegex(checker.InventoryError, expected_error),
            ):
                aws.call("ec2", "describe-vpcs")

    def test_recorded_aws_shapes_normalize_to_snapshot_contract(self) -> None:
        raw_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "ssm:GetParameter",
                    "Resource": "*",
                }
            ],
        }
        endpoint = checker._normalize_endpoint(
            {
                "VpcEndpointId": "vpce-123",
                "ServiceName": "com.amazonaws.us-east-2.ecr.api",
                "VpcEndpointType": "Interface",
                "State": "available",
                "PrivateDnsEnabled": True,
                "SubnetIds": ["subnet-b", "subnet-a"],
                "RouteTableIds": ["rtb-b", "rtb-a"],
                "Groups": [{"GroupId": "sg-b"}, {}, {"GroupId": "sg-a"}],
                # EC2 has returned this field URL encoded in multiple CLI/API
                # paths; preserve a recorded wire-compatible shape here.
                "PolicyDocument": checker.urllib.parse.quote(json.dumps(raw_policy)),
            }
        )
        self.assertEqual("ecr.api", endpoint["service"])
        self.assertEqual(["subnet-a", "subnet-b"], endpoint["subnet_ids"])
        self.assertEqual(["rtb-a", "rtb-b"], endpoint["route_table_ids"])
        self.assertEqual(["sg-a", "sg-b"], endpoint["security_group_ids"])
        self.assertEqual(raw_policy, endpoint["policy"])

        security_group = checker._normalize_sg(
            {
                "GroupId": "sg-relay",
                "VpcId": "vpc-dmz",
                "GroupName": "relay",
                "Tags": [{"Key": "Environment", "Value": "sandbox"}],
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/64"}],
                        "PrefixListIds": [{"PrefixListId": "pl-s3"}],
                        "UserIdGroupPairs": [
                            {
                                "GroupId": "sg-alb",
                                "VpcId": "vpc-dmz",
                                "PeeringStatus": "active",
                            }
                        ],
                    }
                ],
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [],
                    }
                ],
            }
        )
        self.assertEqual({"Environment": "sandbox"}, security_group["tags"])
        self.assertEqual(
            {"cidr_ipv4", "cidr_ipv6", "prefix_list", "security_group"},
            {row["source_type"] for row in security_group["inbound"]},
        )
        peer_rule = next(
            row
            for row in security_group["inbound"]
            if row["source_type"] == "security_group"
        )
        self.assertEqual("sg-alb", peer_rule["source"])
        self.assertEqual("none", security_group["outbound"][0]["source_type"])

        self.assertEqual(
            {
                "destination": "pl-s3",
                "target_type": "peering",
                "target": "pcx-main",
                "state": "active",
            },
            checker._route(
                {
                    "DestinationPrefixListId": "pl-s3",
                    "VpcPeeringConnectionId": "pcx-main",
                    "State": "active",
                }
            ),
        )

    def test_collect_structural_assembles_recorded_aws_responses(self) -> None:
        for dmz_is_requester in (True, False):
            with self.subTest(dmz_is_requester=dmz_is_requester):
                aws = RecordedStructuralAws(dmz_is_requester=dmz_is_requester)
                snapshot = checker.collect_structural("sandbox", aws)

                self.assertEqual("vpc-main-recorded", snapshot["peer"]["main_vpc_id"])
                self.assertEqual("10.100.0.0/16", snapshot["peer"]["main_vpc_cidr"])
                self.assertTrue(snapshot["peer"]["dmz_dns_resolution"])
                self.assertFalse(snapshot["peer"]["main_dns_resolution"])
                self.assertIn(
                    (
                        "ec2",
                        "describe-vpcs",
                        ("--vpc-ids", "vpc-main-recorded"),
                    ),
                    aws.calls,
                )
                self.assertEqual(
                    "arn:aws:logs:us-east-2:767397897469:log-group:"
                    "/layerv/nhp/sandbox/relay-dmz/flow",
                    snapshot["flow_logs"][0]["destination_arn"],
                )
                self.assertNotEqual(
                    "must-not-be-used-as-destination",
                    snapshot["flow_logs"][0]["destination_arn"],
                )
                self.assertEqual(
                    {
                        "vpc_id": "vpc-dmz-recorded",
                        "protocol": "HTTPS",
                        "port": 8080,
                        "target_type": "instance",
                        "health_check_path": "/health/live",
                        "health_check_matcher": "200",
                    },
                    {
                        key: snapshot["alb"]["target_groups"][0][key]
                        for key in (
                            "vpc_id",
                            "protocol",
                            "port",
                            "target_type",
                            "health_check_path",
                            "health_check_matcher",
                        )
                    },
                )
                self.assertEqual("true", snapshot["alb"]["access_logs_enabled"])
                self.assertEqual("defensive", snapshot["alb"]["desync_mitigation_mode"])
                self.assertEqual(
                    {
                        "name": "native.nhp.layerv.xyz",
                        "hosted_zone_id": "Z10394893FM38A1RXLL32",
                        "type": "A",
                        "alias_dns_name": RECORDED_NATIVE_LB_DNS,
                        "alias_hosted_zone_id": NATIVE_LB_ZONE_ID,
                        "evaluate_target_health": True,
                    },
                    {
                        key: snapshot["native_dns"][key]
                        for key in (
                            "name",
                            "hosted_zone_id",
                            "type",
                            "alias_dns_name",
                            "alias_hosted_zone_id",
                            "evaluate_target_health",
                        )
                    },
                )
                self.assertEqual(2, len(snapshot["native_alarms"]["metric_alarms"]))
                self.assertEqual([], snapshot["native_alarms"]["composite_alarm_names"])
                self.assertEqual(
                    RECORDED_NATIVE_LB_DNS, snapshot["native_nlb"]["dns_name"]
                )
                self.assertEqual(
                    NATIVE_LB_ZONE_ID,
                    snapshot["native_nlb"]["canonical_hosted_zone_id"],
                )
                partial_alarm = native_alarm_for(snapshot, "-unhealthy")
                self.assertEqual(
                    {
                        "actions_enabled": True,
                        "state_value": "OK",
                        "alarm_actions": [NATIVE_ALARM_ACTION_ARN],
                        "ok_actions": [NATIVE_ALARM_ACTION_ARN],
                        "metric_name": "UnHealthyHostCount",
                        "statistic": "Maximum",
                        "unit": None,
                        "threshold": 0,
                        "dimension_count": 2,
                        "metric_query_count": 0,
                        "dimensions": {
                            "LoadBalancer": "net/relay-nhp/def456",
                            "TargetGroup": "targetgroup/rlyudp-recorded/789abc",
                        },
                    },
                    {
                        key: partial_alarm[key]
                        for key in (
                            "actions_enabled",
                            "state_value",
                            "alarm_actions",
                            "ok_actions",
                            "metric_name",
                            "statistic",
                            "unit",
                            "threshold",
                            "dimension_count",
                            "metric_query_count",
                            "dimensions",
                        )
                    },
                )
                self.assertIn(
                    (
                        "route53",
                        "list-resource-record-sets",
                        (
                            "--hosted-zone-id",
                            "Z10394893FM38A1RXLL32",
                            "--start-record-name",
                            "native.nhp.layerv.xyz",
                            "--start-record-type",
                            "A",
                            "--max-items",
                            "1",
                        ),
                    ),
                    aws.calls,
                )
                self.assertIn(
                    (
                        "cloudwatch",
                        "describe-alarms",
                        (
                            "--alarm-names",
                            "layerv-nhp-sandbox-relay-native-nlb-unhealthy",
                            "layerv-nhp-sandbox-relay-native-nlb-zero-healthy",
                        ),
                    ),
                    aws.calls,
                )
                self.assertEqual(
                    ["tg-dmz-orphan-recorded", "tg-old-recorded"],
                    snapshot["orphaned_legacy_resources"]["target_groups"],
                )
                self.assertEqual(
                    [],
                    snapshot["orphaned_legacy_resources"][
                        "public_main_vpc_nhp_listeners"
                    ],
                )
                self.assertEqual(
                    [
                        {
                            "action": "BLOCK",
                            "priority": 100,
                            "dns_threat_protection": "DGA",
                            "confidence_threshold": "HIGH",
                            "block_response": "NODATA",
                            "redirection_action": None,
                            "domains": [],
                        },
                        {
                            "action": "ALLOW",
                            "priority": 200,
                            "dns_threat_protection": None,
                            "confidence_threshold": None,
                            "block_response": None,
                            "redirection_action": "TRUST_REDIRECTION_DOMAIN",
                            "domains": ["logs.us-east-2.amazonaws.com"],
                        },
                        {
                            "action": "BLOCK",
                            "priority": 900,
                            "dns_threat_protection": None,
                            "confidence_threshold": None,
                            "block_response": "NODATA",
                            "redirection_action": None,
                            "domains": ["*"],
                        },
                    ],
                    snapshot["resolver"]["firewall_associations"][0]["rules"],
                )
                self.assertEqual(
                    {
                        "association_status": "ACTIVE",
                        "status": "CREATED",
                        "destination_arn": (
                            "arn:aws:logs:us-east-2:767397897469:log-group:"
                            "/layerv/nhp/sandbox/relay-dmz/resolver"
                        ),
                        "name": "relay-resolver-recorded",
                    },
                    snapshot["resolver"]["query_log_configs"][0],
                )
                self.assertEqual("DISABLED", snapshot["resolver"]["firewall_fail_open"])

        aws = RecordedStructuralAws(dmz_is_requester=True, empty_main_vpc=True)
        with self.assertRaisesRegex(
            checker.RetryableInventoryError,
            "main VPC 'vpc-main-recorded' resolved to 0 VPCs",
        ) as raised:
            checker.collect_structural("sandbox", aws)
        self.assertTrue(checker._retryable_inventory_error(raised.exception))

        aws = RecordedStructuralAws(dmz_is_requester=True, empty_dmz_vpc=True)
        with self.assertRaisesRegex(
            checker.RetryableInventoryError,
            "relay DMZ VPC 'vpc-dmz-recorded' resolved to 0 VPCs",
        ) as raised:
            checker.collect_structural("sandbox", aws)
        self.assertTrue(checker._retryable_inventory_error(raised.exception))

    def test_collect_structural_records_public_main_vpc_nhp_listener_by_shape(
        self,
    ) -> None:
        cases = (
            ("layerv-nhp-sandbox-nlb", "UDP"),
            ("renamed-rogue-edge", "TCP_UDP"),
        )
        for load_balancer_name, protocol in cases:
            with self.subTest(name=load_balancer_name, protocol=protocol):
                aws = RecordedStructuralAws(
                    dmz_is_requester=True,
                    public_main_vpc_nhp_protocol=protocol,
                    public_main_vpc_nhp_name=load_balancer_name,
                )
                snapshot = checker.collect_structural("sandbox", aws)
                self.assertEqual(
                    [
                        {
                            "load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-2:767397897469:loadbalancer/net/public-main-nhp/legacy",
                            "load_balancer_name": load_balancer_name,
                            "listener_arn": "listener-public-main-nhp",
                            "protocol": protocol,
                            "port": 62206,
                        }
                    ],
                    snapshot["orphaned_legacy_resources"][
                        "public_main_vpc_nhp_listeners"
                    ],
                )
                self.assertTrue(
                    any(
                        "legacy public main-VPC UDP-capable 62206 listeners remain"
                        in error
                        for error in checker.validate_structural(snapshot)
                    )
                )

    def test_collect_structural_rejects_peer_without_main_vpc_id(self) -> None:
        for dmz_is_requester in (True, False):
            with self.subTest(dmz_is_requester=dmz_is_requester):
                aws = RecordedStructuralAws(
                    dmz_is_requester=dmz_is_requester,
                    missing_main_peer_vpc_id=True,
                )

                with self.assertRaisesRegex(
                    checker.InventoryError,
                    "active relay VPC peer lacks a valid main VPC ID",
                ):
                    checker.collect_structural("sandbox", aws)
                describe_vpc_calls = [
                    args
                    for service, operation, args in aws.calls
                    if service == "ec2" and operation == "describe-vpcs"
                ]
                self.assertEqual([], describe_vpc_calls)

    def test_collector_singleton_cardinality_classification_at_raise_site(
        self,
    ) -> None:
        class CardinalityAws(RecordedStructuralAws):
            def __init__(self, target: str, count: int):
                super().__init__(dmz_is_requester=True)
                self.target = target
                self.count = count

            def call(self, service: str, operation: str, *args: str) -> dict:
                result = copy.deepcopy(super().call(service, operation, *args))
                if (service, operation) == (
                    "autoscaling",
                    "describe-auto-scaling-groups",
                ) and self.target == "asg":
                    rows = result["AutoScalingGroups"]
                    result["AutoScalingGroups"] = (
                        [] if self.count == 0 else [rows[0], copy.deepcopy(rows[0])]
                    )
                elif (service, operation) == (
                    "elbv2",
                    "describe-load-balancers",
                ) and self.target in {"alb", "native"}:
                    wanted_type = "application" if self.target == "alb" else "network"
                    rows = result["LoadBalancers"]
                    matched = [row for row in rows if row.get("Type") == wanted_type]
                    others = [row for row in rows if row.get("Type") != wanted_type]
                    result["LoadBalancers"] = (
                        others
                        if self.count == 0
                        else [*others, matched[0], copy.deepcopy(matched[0])]
                    )
                elif (service, operation) == (
                    "ec2",
                    "describe-vpc-peering-connections",
                ) and self.target == "peer":
                    rows = result["VpcPeeringConnections"]
                    if self.count == 0:
                        result["VpcPeeringConnections"] = []
                    elif rows:
                        duplicate = copy.deepcopy(rows[0])
                        duplicate["VpcPeeringConnectionId"] = "pcx-recorded-duplicate"
                        result["VpcPeeringConnections"] = [rows[0], duplicate]
                return result

        expectations = {
            "asg": "canonical ASG 'layerv-nhp-sandbox-relay-dmz' resolved to {count} groups",
            "alb": "relay DMZ VPC has {count} canonical ALBs",
            "native": "relay DMZ VPC has {count} canonical native NHP NLBs",
            "peer": "relay DMZ VPC has {count} active peers",
        }
        for target, message in expectations.items():
            for count, error_type in (
                (0, checker.RetryableInventoryError),
                (2, checker.InventoryError),
            ):
                with self.subTest(target=target, count=count):
                    with self.assertRaisesRegex(
                        error_type, re.escape(message.format(count=count))
                    ) as raised:
                        checker.collect_structural(
                            "sandbox", CardinalityAws(target, count)
                        )
                    self.assertEqual(
                        count == 0,
                        checker._retryable_inventory_error(raised.exception),
                    )

    def test_collect_structural_rejects_empty_security_group_id_set(self) -> None:
        aws = RecordedStructuralAws(dmz_is_requester=True, empty_dmz_sg_ids=True)

        with self.assertRaisesRegex(
            checker.InventoryError, "resolved to no security group IDs"
        ):
            checker.collect_structural("sandbox", aws)

        self.assertFalse(
            any(
                service == "ec2"
                and operation == "describe-security-groups"
                and "--group-ids" in args
                for service, operation, args in aws.calls
            ),
            aws.calls,
        )

    def test_collect_structural_rejects_untagged_lb_reusing_canonical_sg(
        self,
    ) -> None:
        aws = RecordedStructuralAws(
            dmz_is_requester=True,
            extra_untagged_lb_reuses_alb_sg=True,
        )

        with self.assertRaisesRegex(
            checker.InventoryError,
            "noncanonical DMZ load balancers reuse a canonical relay edge security group",
        ):
            checker.collect_structural("sandbox", aws)

    def test_collect_structural_ignores_missing_server_security_group_id(self) -> None:
        aws = RecordedStructuralAws(dmz_is_requester=True)
        original_normalize_sg = checker._normalize_sg

        def normalize_sg(group: dict) -> dict:
            normalized = original_normalize_sg(group)
            if group.get("GroupId") == "sg-relay-recorded":
                normalized["inbound"] = [
                    {
                        "protocol": "udp",
                        "from": checker.RELAY_ACK_UDP_PORT,
                        "to": checker.RELAY_ACK_UDP_PORT,
                        "source_type": "security_group",
                        "source": "sg-server-recorded",
                    },
                    {
                        "protocol": "udp",
                        "from": checker.RELAY_ACK_UDP_PORT,
                        "to": checker.RELAY_ACK_UDP_PORT,
                        "source_type": "security_group",
                        "source": None,
                    },
                ]
            return normalized

        with mock.patch.object(checker, "_normalize_sg", side_effect=normalize_sg):
            checker.collect_structural("sandbox", aws)

        server_group_calls = [
            args
            for service, operation, args in aws.calls
            if service == "ec2"
            and operation == "describe-security-groups"
            and "sg-server-recorded" in args
        ]
        self.assertEqual(1, len(server_group_calls))
        self.assertNotIn(None, server_group_calls[0])

    def test_waf_nonexistent_error_normalizes_to_missing_waf_violation(self) -> None:
        aws = RecordedStructuralAws(dmz_is_requester=True, waf_absent=True)

        snapshot = checker.collect_structural("sandbox", aws)

        self.assertIsNone(snapshot["alb"]["waf_arn"])
        self.assertIn(
            "canonical relay ALB has no WAF association",
            checker.validate_structural(snapshot),
        )

    def test_collect_functional_normalizes_mocked_aws_responses(self) -> None:
        snapshot = good_snapshot()
        instance_ids = snapshot["canonical_asg"]["instance_ids"]
        aws = mock.Mock()

        def call(service: str, operation: str, *args: str) -> dict:
            if (service, operation) == ("elbv2", "describe-target-health"):
                return {
                    "TargetHealthDescriptions": [
                        {
                            "Target": {"Id": instance_id},
                            "TargetHealth": {"State": "healthy"},
                        }
                        for instance_id in instance_ids
                    ]
                }
            if (service, operation) == ("ssm", "describe-instance-information"):
                filters = json.loads(args[-1])
                self.assertEqual(
                    [{"Key": "InstanceIds", "Values": instance_ids}], filters
                )
                return {
                    "InstanceInformationList": [
                        {
                            "InstanceId": instance_id,
                            "PingStatus": "Online",
                            "AgentVersion": "3.3.40.0",
                            "PlatformName": "Ubuntu",
                        }
                        for instance_id in instance_ids
                    ]
                }
            if (service, operation) == ("guardduty", "list-detectors"):
                return {"DetectorIds": ["detector-1"]}
            if (service, operation) == ("guardduty", "list-coverage"):
                return {
                    "Resources": [
                        {
                            "CoverageStatus": "HEALTHY",
                            "Issue": None,
                            "ResourceDetails": {
                                "Ec2InstanceDetails": {
                                    "InstanceId": instance_id,
                                    "AgentDetails": {"Version": "1.0.0"},
                                    "ManagementType": "AUTO_MANAGED",
                                }
                            },
                        }
                        for instance_id in instance_ids
                    ]
                }
            if (service, operation) == ("ssm", "describe-document"):
                return run_shell_document_description()
            if (service, operation) == ("ssm", "send-command"):
                self.assertIn("AWS-RunShellScript", args)
                self.assertEqual("1", args[args.index("--document-version") + 1])
                self.assertEqual("a" * 64, args[args.index("--document-hash") + 1])
                self.assertEqual("Sha256", args[args.index("--document-hash-type") + 1])
                parameters = json.loads(args[args.index("--parameters") + 1])
                command = parameters["commands"][0]
                self.assertIn('socket.getaddrinfo("example.com", None)', command)
                self.assertIn("sock.connect_ex", command)
                self.assertIn("errno.ECONNREFUSED", command)
                self.assertIn("errno.ENETUNREACH", command)
                self.assertIn('[ "$probe_error" -eq 0 ] || exit 2', command)
                self.assertIn("systemctl is-active", command)
                self.assertIn("for target in 1.1.1.1 8.8.8.8", command)
                for host in checker._expected_dns_domains("us-east-2"):
                    if "*" not in host:
                        self.assertIn(host, command)
                return {"Command": {"CommandId": "command-1"}}
            if (service, operation) == ("ssm", "get-command-invocation"):
                return {
                    "Status": "Success",
                    "StandardOutputContent": (
                        "NHP_DMZ_PROBE allowed_dns=1 blocked_public_dns=1 "
                        "public_tcp_unreachable=1 relay_active=1\n"
                    ),
                }
            self.fail(f"unexpected AWS call: {service} {operation} {args}")

        aws.call.side_effect = call
        checker.collect_functional(snapshot, aws)

        functional = snapshot["functional"]
        self.assertEqual(
            set(instance_ids),
            {row["instance_id"] for row in functional["target_health"]},
        )
        self.assertTrue(
            all(
                row["state"] == "healthy" and row["reason"] is None
                for row in functional["target_health"]
            )
        )
        self.assertEqual(
            set(instance_ids), {row["instance_id"] for row in functional["ssm"]}
        )
        self.assertTrue(
            all(
                row["ping_status"] == "Online"
                and row["agent_version"] == "3.3.40.0"
                and row["platform"] == "Ubuntu"
                for row in functional["ssm"]
            )
        )
        self.assertEqual(
            set(instance_ids),
            {row["instance_id"] for row in functional["guardduty_coverage"]},
        )
        self.assertTrue(
            all(
                row["status"] == "HEALTHY"
                and row["issue"] is None
                and row["agent_version"] == "1.0.0"
                and row["management_type"] == "AUTO_MANAGED"
                for row in functional["guardduty_coverage"]
            )
        )
        self.assertEqual(
            set(instance_ids), {row["instance_id"] for row in functional["probes"]}
        )
        self.assertTrue(
            all(
                row["status"] == "Success"
                and row["allowed_dns"]
                and row["blocked_public_dns"]
                and row["public_tcp_unreachable"]
                and row["relay_active"]
                for row in functional["probes"]
            )
        )

    def test_collect_functional_skips_instance_apis_for_empty_fleet(self) -> None:
        snapshot = good_snapshot()
        snapshot["canonical_asg"]["instance_ids"] = []
        aws = mock.Mock()
        aws.call.return_value = {}

        checker.collect_functional(snapshot, aws)

        operations = [call.args[1] for call in aws.call.call_args_list]
        self.assertNotIn("describe-instance-information", operations)
        self.assertNotIn("send-command", operations)
        self.assertNotIn("get-command-invocation", operations)
        self.assertEqual([], snapshot["functional"]["ssm"])
        self.assertEqual([], snapshot["functional"]["probes"])

    def test_collect_functional_rejects_untrusted_region_before_aws_calls(self) -> None:
        snapshot = good_snapshot()
        snapshot["region"] = "us-east-2; touch /tmp/pwned"
        aws = mock.Mock()
        with self.assertRaisesRegex(
            checker.InventoryError, "not a valid commercial partition region"
        ):
            checker.collect_functional(snapshot, aws)
        aws.call.assert_not_called()

    def test_collect_functional_rejects_untrusted_account_before_aws_calls(
        self,
    ) -> None:
        snapshot = good_snapshot()
        snapshot["account_id"] = "123456789012; touch /tmp/pwned"
        aws = mock.Mock()
        with self.assertRaisesRegex(
            checker.InventoryError, "not a 12-digit identifier"
        ):
            checker.collect_functional(snapshot, aws)
        aws.call.assert_not_called()

    def test_collect_functional_rejects_iam_dark_prod_before_aws_calls(self) -> None:
        snapshot = good_snapshot()
        snapshot["environment"] = "prod"
        aws = mock.Mock()

        with self.assertRaisesRegex(
            checker.InventoryError,
            "prod relay DMZ functional mode is IAM-dark",
        ):
            checker.collect_functional(snapshot, aws)

        aws.call.assert_not_called()

    def test_collect_functional_rejects_unknown_environment_before_aws_calls(
        self,
    ) -> None:
        snapshot = good_snapshot()
        snapshot["environment"] = "staging"
        aws = mock.Mock()

        with self.assertRaisesRegex(
            checker.InventoryError,
            "live relay DMZ functional mode is not authorized",
        ):
            checker.collect_functional(snapshot, aws)

        aws.call.assert_not_called()

    def test_prod_live_functional_cli_fails_before_aws_client(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(checker, "AwsCli") as aws_cli,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(["--environment", "prod", "--mode", "functional"])

        self.assertEqual(2, result)
        self.assertIn("prod relay DMZ functional mode is IAM-dark", output.getvalue())
        aws_cli.assert_not_called()

    def test_ssm_run_shell_document_pin_rejects_untrusted_metadata(self) -> None:
        cases = {
            "owner": ({"Owner": "123456789012"}, "Owner is not 'Amazon'"),
            "type": ({"DocumentType": "Automation"}, "DocumentType is not 'Command'"),
            "status": ({"Status": "Updating"}, "Status is not 'Active'"),
            "hash type": ({"HashType": "Sha1"}, "HashType is not 'Sha256'"),
            "version": ({"DocumentVersion": "$DEFAULT"}, "version is not numeric"),
            "hash": ({"Hash": "not-a-hash"}, "SHA-256 hash is invalid"),
        }
        for label, (overrides, message) in cases.items():
            with self.subTest(label=label):
                aws = mock.Mock()
                aws.call.return_value = run_shell_document_description(**overrides)
                with self.assertRaisesRegex(checker.InventoryError, message):
                    checker._pin_ssm_run_shell_document(aws)

    def test_collect_functional_caches_only_fully_successful_probes(self) -> None:
        first = good_snapshot()
        first["canonical_asg"]["instance_ids"] = ["i-pass", "i-retry"]
        second = good_snapshot()
        second["canonical_asg"]["instance_ids"] = [
            "i-pass",
            "i-retry",
            "i-new",
        ]
        cache: dict[str, dict] = {}
        aws = mock.Mock()
        send_batches: list[list[str]] = []

        def call(service: str, operation: str, *args: str) -> dict:
            if (service, operation) == ("ssm", "describe-document"):
                return run_shell_document_description()
            if (service, operation) == ("ssm", "send-command"):
                start = args.index("--instance-ids") + 1
                end = args.index("--parameters")
                batch = list(args[start:end])
                send_batches.append(batch)
                return {"Command": {"CommandId": f"command-{len(send_batches)}"}}
            if (service, operation) == ("ssm", "get-command-invocation"):
                instance_id = args[args.index("--instance-id") + 1]
                relay_active = (
                    "0" if len(send_batches) == 1 and instance_id == "i-retry" else "1"
                )
                return {
                    "Status": "Success",
                    "StandardOutputContent": (
                        "NHP_DMZ_PROBE allowed_dns=1 blocked_public_dns=1 "
                        f"public_tcp_unreachable=1 relay_active={relay_active}\n"
                    ),
                }
            return {}

        aws.call.side_effect = call
        used_cache = checker.collect_functional(first, aws, cache)

        self.assertFalse(used_cache)
        self.assertEqual([["i-pass", "i-retry"]], send_batches)
        self.assertEqual({"i-pass"}, set(cache))
        self.assertFalse(
            next(
                probe
                for probe in first["functional"]["probes"]
                if probe["instance_id"] == "i-retry"
            )["relay_active"]
        )

        used_cache = checker.collect_functional(second, aws, cache)

        self.assertTrue(used_cache)
        self.assertEqual(["i-retry", "i-new"], send_batches[1])
        self.assertEqual({"i-pass", "i-retry", "i-new"}, set(cache))
        self.assertEqual(
            {"i-pass", "i-retry", "i-new"},
            {probe["instance_id"] for probe in second["functional"]["probes"]},
        )

    def test_collect_functional_rejects_empty_command_id(self) -> None:
        snapshot = good_snapshot()
        snapshot["canonical_asg"]["instance_ids"] = ["i-relay"]
        aws = mock.Mock()

        def call(service: str, operation: str, *args: str) -> dict:
            if (service, operation) == ("ssm", "describe-document"):
                return run_shell_document_description()
            if (service, operation) == ("ssm", "send-command"):
                return {"Command": {}}
            return {}

        aws.call.side_effect = call
        with self.assertRaisesRegex(
            checker.InventoryError, "send-command returned an empty CommandId"
        ):
            checker.collect_functional(snapshot, aws, {})

    def test_ssm_probe_polls_inprogress_and_delayed_until_success(self) -> None:
        snapshot = good_snapshot()
        snapshot["canonical_asg"]["instance_ids"] = ["i-relay-0"]
        success = {
            "Status": "Success",
            "StandardOutputContent": (
                "NHP_DMZ_PROBE allowed_dns=1 blocked_public_dns=1 "
                "public_tcp_unreachable=1 relay_active=1\n"
            ),
        }
        aws = functional_probe_aws(
            [{"Status": "InProgress"}, {"Status": "Delayed"}, success]
        )
        with (
            mock.patch.object(
                checker.time,
                "monotonic",
                side_effect=[0.0, 0.0, 0.0, 1.0, 1.0, 2.0],
            ),
            mock.patch.object(checker.time, "sleep") as sleep,
        ):
            checker.collect_functional(snapshot, aws)

        self.assertEqual(
            [
                {
                    "instance_id": "i-relay-0",
                    "status": "Success",
                    "allowed_dns": True,
                    "blocked_public_dns": True,
                    "public_tcp_unreachable": True,
                    "relay_active": True,
                }
            ],
            snapshot["functional"]["probes"],
        )
        self.assertEqual(
            [
                mock.call(checker.SSM_PROBE_POLL_INTERVAL_SECONDS),
                mock.call(checker.SSM_PROBE_POLL_INTERVAL_SECONDS),
            ],
            sleep.call_args_list,
        )

    def test_ssm_probe_retries_invocation_does_not_exist_until_success(self) -> None:
        snapshot = good_snapshot()
        snapshot["canonical_asg"]["instance_ids"] = ["i-relay-0"]
        aws = functional_probe_aws(
            [
                checker.InventoryError("InvocationDoesNotExist"),
                {
                    "Status": "Success",
                    "StandardOutputContent": (
                        "NHP_DMZ_PROBE allowed_dns=1 blocked_public_dns=1 "
                        "public_tcp_unreachable=1 relay_active=1\n"
                    ),
                },
            ]
        )
        with (
            mock.patch.object(
                checker.time, "monotonic", side_effect=[0.0, 0.0, 0.0, 1.0]
            ),
            mock.patch.object(checker.time, "sleep") as sleep,
        ):
            checker.collect_functional(snapshot, aws)

        self.assertEqual("Success", snapshot["functional"]["probes"][0]["status"])
        sleep.assert_called_once_with(checker.SSM_PROBE_POLL_INTERVAL_SECONDS)

    def test_ssm_probe_never_terminal_becomes_timed_out(self) -> None:
        snapshot = good_snapshot()
        snapshot["canonical_asg"]["instance_ids"] = ["i-relay-0"]
        aws = functional_probe_aws([{"Status": "InProgress"}])
        with (
            mock.patch.object(
                checker.time,
                "monotonic",
                side_effect=[
                    0.0,
                    0.0,
                    checker.SSM_PROBE_DEADLINE_SECONDS - 0.5,
                    checker.SSM_PROBE_DEADLINE_SECONDS + 1.0,
                ],
            ),
            mock.patch.object(checker.time, "sleep") as sleep,
        ):
            checker.collect_functional(snapshot, aws)

        self.assertEqual(
            [{"instance_id": "i-relay-0", "status": "TimedOut"}],
            snapshot["functional"]["probes"],
        )
        sleep.assert_called_once_with(0.5)

    def test_good_snapshot_passes_structural_and_functional(self) -> None:
        snapshot = good_snapshot()
        self.assertEqual([], checker.validate_snapshot(snapshot, "structural"))
        self.assertEqual([], checker.validate_snapshot(snapshot, "functional"))

    def test_flow_log_format_order_is_exact(self) -> None:
        snapshot = good_snapshot()
        fields = snapshot["flow_logs"][0]["log_format"].split()
        fields[0], fields[1] = fields[1], fields[0]
        snapshot["flow_logs"][0]["log_format"] = " ".join(fields)
        errors = checker.validate_snapshot(snapshot, "structural")
        self.assertTrue(any("no healthy ALL-traffic" in error for error in errors))

    def test_prod_snapshot_passes_with_prod_retention_contract(self) -> None:
        snapshot = good_prod_snapshot()

        self.assertEqual([], checker.validate_snapshot(snapshot, "structural"))
        self.assertEqual([], checker.validate_snapshot(snapshot, "functional"))

    def test_prod_functional_snapshot_is_offline_and_does_not_cross_live_fence(
        self,
    ) -> None:
        snapshot = good_prod_snapshot()

        with tempfile.NamedTemporaryFile("w", suffix=".json") as fixture:
            json.dump(snapshot, fixture)
            fixture.flush()
            with (
                mock.patch.object(checker, "AwsCli") as aws_cli,
                mock.patch.object(
                    checker, "_require_live_functional_authorized"
                ) as live_fence,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = checker.main(
                    [
                        "--environment",
                        "prod",
                        "--mode",
                        "functional",
                        "--snapshot",
                        fixture.name,
                    ]
                )

        self.assertEqual(0, result)
        aws_cli.assert_not_called()
        live_fence.assert_not_called()

    def test_environment_network_contracts_are_explicit_and_pinned(self) -> None:
        expected = {
            "vpc": "10.101.0.0/16",
            "public-alb": {"10.101.0.0/24", "10.101.1.0/24", "10.101.2.0/24"},
            "isolated-relay": {
                "10.101.10.0/24",
                "10.101.11.0/24",
                "10.101.12.0/24",
            },
            "isolated-endpoint": {
                "10.101.20.0/24",
                "10.101.21.0/24",
                "10.101.22.0/24",
            },
        }
        self.assertEqual({"sandbox", "prod"}, set(checker.RELAY_DMZ_NETWORK_CONTRACTS))
        for environment in ("sandbox", "prod"):
            with self.subTest(environment=environment):
                self.assertEqual(
                    expected, checker.RELAY_DMZ_NETWORK_CONTRACTS[environment]
                )
        self.assertIsNot(
            checker.RELAY_DMZ_NETWORK_CONTRACTS["sandbox"],
            checker.RELAY_DMZ_NETWORK_CONTRACTS["prod"],
        )

    def test_terraform_plan_and_live_contract_constants_stay_in_lockstep(self) -> None:
        root_main_tf = (REPO_ROOT / "terraform/main.tf").read_text()
        alb_tf = (REPO_ROOT / "terraform/modules/relay/alb.tf").read_text()
        relay_main_tf = (REPO_ROOT / "terraform/modules/relay/main.tf").read_text()
        relay_variables_tf = (
            REPO_ROOT / "terraform/modules/relay/variables.tf"
        ).read_text()
        monitoring_tf = (REPO_ROOT / "terraform/modules/monitoring/main.tf").read_text()
        plan_checker = (
            REPO_ROOT / ".github/scripts/check-relay-dmz-plan.py"
        ).read_text()

        # Coarse but load-bearing drift fence: these values are authored in
        # Terraform and mirrored by the live detector's exact boundary checks.
        for expected in (
            f'relay_tg_name_prefix = "{checker.RELAY_TG_NAME_PREFIX}"',
            f'path                = "{checker.RELAY_HEALTH_PATH}"',
            f'ssl_policy        = "{checker.RELAY_TLS_POLICY}"',
        ):
            self.assertIn(expected, alb_tf)
        self.assertRegex(
            relay_variables_tf,
            rf'(?s)variable "listen_port".*?default\s+=\s+{checker.RELAY_BACKEND_PORT}\b',
        )
        self.assertRegex(
            relay_variables_tf,
            rf'(?s)variable "udp_listen_port".*?default\s+=\s+{checker.RELAY_ACK_UDP_PORT}\b',
        )
        self.assertIn(f"s.port == {checker.RELAY_SERVER_UDP_PORT}", relay_variables_tf)
        self.assertIn(
            f"nhp_server_udp_port = {checker.RELAY_SERVER_UDP_PORT}", relay_main_tf
        )
        self.assertIn(
            'name         = "${var.name_prefix}-${var.cell_id}-alerts"', monitoring_tf
        )
        self.assertIn('name_prefix = "layerv-nhp-${var.environment}"', root_main_tf)
        for environment in ("sandbox", "prod"):
            environment_variables = (
                REPO_ROOT / f"terraform/environments/{environment}/variables.tf"
            ).read_text()
            environment_tfvars = (
                REPO_ROOT / f"terraform/environments/{environment}/terraform.tfvars"
            ).read_text()
            self.assertRegex(
                environment_variables,
                r'(?s)variable "cell_id".*?default\s+=\s+"cell0"',
            )
            native_dns = checker.EXPECTED_NATIVE_DNS[environment]
            domain_name = native_dns["fqdn"].removeprefix("native.")
            hosted_zone = domain_name.removeprefix("nhp.")
            self.assertRegex(
                environment_tfvars,
                rf'(?m)^domain_name\s+=\s+"{re.escape(domain_name)}"\s*(?:#.*)?$',
            )
            self.assertRegex(
                environment_tfvars,
                rf'(?m)^hosted_zone\s+=\s+"{re.escape(hosted_zone)}"\s*(?:#.*)?$',
            )
            # Prod bypasses lookup with the root hosted_zone_id. Sandbox owns
            # the zone and resolves it by name; qurl_hosted_zone_id pins the
            # same layerv.xyz zone ID in that environment file.
            zone_id_variable = (
                "hosted_zone_id" if environment == "prod" else "qurl_hosted_zone_id"
            )
            self.assertRegex(
                environment_tfvars,
                rf'(?m)^{zone_id_variable}\s+=\s+"{re.escape(native_dns["hosted_zone_id"])}"\s*(?:#.*)?$',
            )

        for contract in checker.RELAY_DMZ_NETWORK_CONTRACTS.values():
            self.assertIn(f'"{contract["vpc"]}"', plan_checker)
            for tier in ("public-alb", "isolated-relay", "isolated-endpoint"):
                for cidr in contract[tier]:
                    self.assertIn(cidr, plan_checker)
        self.assertIn(
            f'EXPECTED_SANDBOX_NATIVE_NHP_FQDN = "{checker.EXPECTED_NATIVE_DNS["sandbox"]["fqdn"]}"',
            plan_checker,
        )
        self.assertIn("relay_native_nlb_unhealthy_targets", plan_checker)
        self.assertIn("relay_native_nlb_zero_healthy_targets", plan_checker)

        # Principal="*" is an intentional authored-shape contract shared with
        # the plan checker, not accidental semantic normalization.
        self.assertIn('statement.get("Principal") == "*"', plan_checker)
        self.assertIn(
            f'rule.values.get("block_response") == "{checker.DNS_BLOCK_RESPONSE}"',
            plan_checker,
        )
        self.assertIn(
            f'block_rule.values.get("block_response") == "{checker.DNS_BLOCK_RESPONSE}"',
            plan_checker,
        )
        for protection, priority in checker.ADVANCED_DNS_PROTECTION_PRIORITIES.items():
            self.assertIn(f'"{protection}": {priority}', plan_checker)
        equivalent_dict_principal = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {"aws:PrincipalAccount": "123456789012"}
                    },
                }
            ]
        }
        self.assertFalse(
            checker._has_cross_account_deny(equivalent_dict_principal, "123456789012")
        )

    def test_workflow_watches_detector_and_runs_its_suite(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/validate-workflows.yml").read_text()
        makefile = (REPO_ROOT / "Makefile").read_text()

        self.assertIn('- "scripts/check-relay-dmz-live.py"', workflow)
        self.assertIn("python3 tests/scripts/test_check_relay_dmz_live.py", workflow)
        self.assertIn("python3 tests/scripts/test_check_relay_dmz_live.py", makefile)

    def test_snapshot_cli_passes_without_aws(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(good_snapshot()))
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT_PATH),
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--snapshot",
                    str(path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("structural check passed", result.stdout)

    def test_snapshot_ipv6_relay_peering_route_is_explicit_violation(self) -> None:
        snapshot = good_snapshot()
        for subnet in snapshot["subnets"]:
            if subnet["tier"] != "isolated-relay":
                continue
            for relay_route in subnet["routes"]:
                if relay_route["target_type"] == "peering":
                    # A canonical IPv6 /24 (no host bits) parses cleanly, so
                    # the explicit IPv4-only route contract must reject it.
                    relay_route["destination"] = "2001:d00::/24"

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(snapshot))
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT_PATH),
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--snapshot",
                    str(path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(1, result.returncode)
        self.assertIn(
            "main VPC and relay peering routes must use IPv4 CIDRs", result.stdout
        )
        self.assertNotIn("unexpected validator failure", result.stdout + result.stderr)

    def test_snapshot_missing_or_invalid_main_vpc_cidr_is_explicit(self) -> None:
        for value in (None, "", 123):
            with self.subTest(value=value):
                snapshot = good_snapshot()
                snapshot["peer"]["main_vpc_cidr"] = value
                errors = checker.validate_structural(snapshot)
                self.assertTrue(
                    any(
                        "missing or invalid main VPC CIDR" in error for error in errors
                    ),
                    errors,
                )

    def test_unexpected_validator_exception_is_exit_two_in_every_mode(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(good_snapshot()))
            with (
                mock.patch.object(
                    checker,
                    "validate_snapshot",
                    side_effect=RuntimeError("validator exploded"),
                ),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(output),
            ):
                snapshot_result = checker.main(
                    [
                        "--environment",
                        "sandbox",
                        "--mode",
                        "structural",
                        "--snapshot",
                        str(path),
                    ]
                )

        self.assertEqual(2, snapshot_result)
        self.assertIn("unexpected validator failure (RuntimeError)", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

        output = io.StringIO()
        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker, "collect_structural", return_value=good_snapshot()
            ),
            mock.patch.object(
                checker,
                "validate_snapshot",
                side_effect=RuntimeError("validator exploded"),
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            live_result = checker.main(
                ["--environment", "sandbox", "--mode", "structural"]
            )

        self.assertEqual(2, live_result)
        self.assertIn("unexpected validator failure (RuntimeError)", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_structural_mutations_fail_closed(self) -> None:
        cases = {
            "public address": lambda data: data["instances"][0].update(
                {"public_ip": "203.0.113.1"}
            ),
            "undersized fleet": lambda data: data["instances"].pop(),
            "ASG member not InService": lambda data: data["canonical_asg"]["members"][
                0
            ].update({"lifecycle_state": "Pending"}),
            "EC2 instance stopped": lambda data: data["instances"][0].update(
                {"state": "stopped"}
            ),
            "legacy ASG remains": lambda data: data["orphaned_legacy_resources"][
                "asgs"
            ].append("layerv-nhp-sandbox-relay"),
            "orphan relay target group remains": lambda data: data[
                "orphaned_legacy_resources"
            ]["target_groups"].append("tg-dmz-orphan"),
            "rogue relay ENI": lambda data: data["relay_network_interfaces"].append(
                {
                    "id": "eni-rogue",
                    "subnet_id": "subnet-relay-0",
                    "private_ip": "10.101.10.99",
                    "public_ip": None,
                    "ipv6": [],
                    "security_group_ids": ["sg-relay"],
                    "status": "in-use",
                }
            ),
            "untagged subnet": lambda data: data["subnets"][0].update({"tier": None}),
            "secondary IPv4 CIDR": lambda data: data["vpc"][
                "ipv4_cidr_associations"
            ].append({"cidr": "10.102.0.0/16", "state": "associating"}),
            "transitional IPv6 CIDR": lambda data: data["vpc"][
                "ipv6_cidr_associations"
            ].append({"cidr": "2001:db8::/56", "state": "disassociating"}),
            "second reverse-direction peer": lambda data: data["peer"].update(
                {"active_peer_count": 2}
            ),
            "relay default route": lambda data: data["subnets"][1]["routes"].append(
                route("0.0.0.0/0", "nat", "nat-bad")
            ),
            "extra public route": lambda data: data["subnets"][0]["routes"].append(
                route("192.0.2.0/24", "transit_gateway", "tgw-bad")
            ),
            "extra relay route": lambda data: data["subnets"][1]["routes"].append(
                route("192.0.2.0/24", "network_interface", "eni-bad")
            ),
            "extra endpoint route": lambda data: data["subnets"][2]["routes"].append(
                route("192.0.2.0/24", "peering", "pcx-bad")
            ),
            "extra relay egress": lambda data: data["security_groups"]["by_id"][
                "sg-relay"
            ]["outbound"].append(rule("tcp", 80, 80, "cidr_ipv4", "0.0.0.0/0")),
            "server broad UDP overlap": lambda data: data["security_groups"]["by_id"][
                "sg-server"
            ]["inbound"].append(rule("udp", 0, 65535, "cidr_ipv4", "0.0.0.0/0")),
            "server all-protocol overlap": lambda data: data["security_groups"][
                "by_id"
            ]["sg-server"]["inbound"].append(
                rule("-1", None, None, "cidr_ipv4", "0.0.0.0/0")
            ),
            "endpoint allow all": lambda data: data["endpoints"][0]["policy"][
                "Statement"
            ][0].update({"Action": "*"}),
            "duplicate interface endpoint": lambda data: data["endpoints"].append(
                copy.deepcopy(data["endpoints"][0])
            ),
            "endpoint unexpected write": lambda data: data["endpoints"][5]["policy"][
                "Statement"
            ][0].update(
                {
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                    ]
                }
            ),
            "noncommercial secret ARN": lambda data: data["endpoints"][5]["policy"][
                "Statement"
            ][0].update(
                {
                    "Resource": "arn:aws-us-gov:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox-relay-abc"
                }
            ),
            "cross-account secret ARN": lambda data: data["endpoints"][5]["policy"][
                "Statement"
            ][0].update(
                {
                    "Resource": "arn:aws:secretsmanager:us-east-2:111122223333:secret:layerv-nhp-sandbox-relay-abc"
                }
            ),
            "duplicate GuardDuty endpoint": lambda data: data["endpoints"].append(
                copy.deepcopy(data["endpoints"][2])
            ),
            "GuardDuty policy extra statement": lambda data: data["endpoints"][2][
                "policy"
            ]["Statement"].append(
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "guardduty:Put",
                    "Resource": "*",
                }
            ),
            "incomplete endpoint deny": lambda data: data["endpoints"][3]["policy"][
                "Statement"
            ][1].update({"Principal": {"AWS": "*"}}),
            "missing main return route": lambda data: data["main_private_routes"][0][
                "routes"
            ].pop(1),
            "legacy main private table": lambda data: data["main_private_routes"][0][
                "route_table_tags"
            ].update({"Name": "layerv-nhp-sandbox-rtb-private-0"}),
            "missing main NAT default": lambda data: data["main_private_routes"][0][
                "routes"
            ].pop(),
            "public relay ENI": lambda data: data["relay_network_interfaces"][0].update(
                {"public_ip": "203.0.113.2"}
            ),
            "DNS fail open": lambda data: data["resolver"].update(
                {"firewall_fail_open": "ENABLED"}
            ),
            "Resolver mutation protection": lambda data: data["resolver"][
                "firewall_associations"
            ][0].update({"mutation_protection": "ENABLED"}),
            "extra Resolver rule": lambda data: data["resolver"][
                "firewall_associations"
            ][0]["rules"].append(
                {
                    "action": "BLOCK",
                    "priority": 850,
                    "domains": ["unexpected.example"],
                    "block_response": "NODATA",
                    "dns_threat_protection": None,
                }
            ),
            "advanced DNS override response": lambda data: data["resolver"][
                "firewall_associations"
            ][0]["rules"][0].update({"block_response": "OVERRIDE"}),
            "fractional advanced DNS priority": lambda data: data["resolver"][
                "firewall_associations"
            ][0]["rules"][0].update({"priority": 100.9}),
            "catch-all DNS override response": lambda data: data["resolver"][
                "firewall_associations"
            ][0]["rules"][-1].update({"block_response": "OVERRIDE"}),
            "fractional catch-all DNS priority": lambda data: data["resolver"][
                "firewall_associations"
            ][0]["rules"][-1].update({"priority": 900.9}),
            "wrong Resolver log destination": lambda data: data["resolver"][
                "query_log_configs"
            ][0].update(
                {
                    "destination_arn": "arn:aws:logs:us-east-2:767397897469:log-group:/wrong"
                }
            ),
            "different log KMS keys": lambda data: data["security_log_groups"][
                "resolver"
            ].update({"kms_key_id": "arn:aws:kms:us-east-2:767397897469:key/wrong"}),
            "broad log KMS context": lambda data: data["logs_kms_policy"]["Statement"][
                1
            ]["Condition"]["ArnEquals"].update(
                {"kms:EncryptionContext:aws:logs:arn": ["*"]}
            ),
            "extra log KMS statement": lambda data: data["logs_kms_policy"][
                "Statement"
            ].append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ),
            "wrong flow log destination": lambda data: data["flow_logs"][0].update(
                {
                    "destination_arn": "arn:aws:logs:us-east-2:767397897469:log-group:/wrong"
                }
            ),
            "target group HTTP": lambda data: data["alb"]["target_groups"][0].update(
                {"protocol": "HTTP"}
            ),
            "target group wrong health": lambda data: data["alb"]["target_groups"][
                0
            ].update({"health_check_path": "/"}),
            "missing WAF": lambda data: data["alb"].update({"waf_arn": None}),
            "ALB deletion protection drift": lambda data: data["alb"].update(
                {"deletion_protection_enabled": "true"}
            ),
            "ALB HTTP hardening drift": lambda data: data["alb"].update(
                {"drop_invalid_headers_enabled": "false"}
            ),
            "ALB XFF client port drift": lambda data: data["alb"].update(
                {"xff_client_port_enabled": "true"}
            ),
            "ALB WAF fail-open drift": lambda data: data["alb"].update(
                {"waf_fail_open_enabled": "true"}
            ),
            "ALB log destination drift": lambda data: data["alb"].update(
                {"access_logs_bucket": "attacker-controlled-bucket"}
            ),
            "ALB ownership tag drift": lambda data: data["alb"]["tags"].pop(
                "Component"
            ),
            "native NHP ack port exposed": lambda data: data["native_nlb"]["listeners"][
                0
            ].update({"port": 62207}),
            "native NHP direct IP targets": lambda data: data["native_nlb"][
                "target_groups"
            ][0].update({"target_type": "ip"}),
            "native NHP client IP lost": lambda data: data["native_nlb"][
                "target_groups"
            ][0].update({"preserve_client_ip": "false"}),
            "native NHP liveness is not readiness": lambda data: data["native_nlb"][
                "target_groups"
            ][0].update({"health_check_path": "/health/live"}),
            "native NHP wrong listener target": lambda data: data["native_nlb"][
                "listeners"
            ][0]["actions"][0].update({"TargetGroupArn": "wrong-tg"}),
            "native NHP missing public subnet": lambda data: data["native_nlb"][
                "subnet_ids"
            ].pop(),
            "native NHP cross-zone off": lambda data: data["native_nlb"].update(
                {"cross_zone_enabled": "false"}
            ),
            "native NHP ownership tag missing": lambda data: data["native_nlb"][
                "tags"
            ].pop("Service"),
            "native stable alias missing": lambda data: data.update(
                {"native_dns": {"record_count": 0}}
            ),
            "native stable alias retargeted": lambda data: data["native_dns"].update(
                {"alias_dns_name": "wrong.elb.us-east-2.amazonaws.com"}
            ),
            "native stable alias wrong zone": lambda data: data["native_dns"].update(
                {"alias_hosted_zone_id": "ZWRONG"}
            ),
            "native stable hosted zone wrong": lambda data: data["native_dns"].update(
                {"hosted_zone_id": "ZWRONG"}
            ),
            "native stable alias health disabled": lambda data: data[
                "native_dns"
            ].update({"evaluate_target_health": False}),
            "native stable alias weighted": lambda data: data["native_dns"].update(
                {"set_identifier": "canary", "weight": 1}
            ),
            "native stable alias address record": lambda data: data[
                "native_dns"
            ].update({"ttl": 60, "resource_record_count": 1}),
            "native partial alarm missing": lambda data: data["native_alarms"][
                "metric_alarms"
            ].remove(native_alarm_for(data, "-unhealthy")),
            "native partial alarm wrong metric": lambda data: native_alarm_for(
                data, "-unhealthy"
            ).update({"metric_name": "HealthyHostCount"}),
            "native partial alarm wrong dimension": lambda data: native_alarm_for(
                data, "-unhealthy"
            )["dimensions"].update({"LoadBalancer": "net/wrong/deadbeef"}),
            "native zero alarm missing": lambda data: data["native_alarms"][
                "metric_alarms"
            ].remove(native_alarm_for(data, "-zero-healthy")),
            "native zero alarm wrong missing policy": lambda data: native_alarm_for(
                data, "-zero-healthy"
            ).update({"treat_missing_data": "notBreaching"}),
            "native zero alarm actions disabled": lambda data: native_alarm_for(
                data, "-zero-healthy"
            ).update({"actions_enabled": False}),
            "native alarm wrong unit": lambda data: native_alarm_for(
                data, "-unhealthy"
            ).update({"unit": "Bytes"}),
            "native alarm duplicate dimension": lambda data: native_alarm_for(
                data, "-unhealthy"
            ).update({"dimension_count": 3}),
            "native alarm metric math": lambda data: native_alarm_for(
                data, "-unhealthy"
            ).update({"metric_query_count": 1}),
            "native alarm cross-account action": lambda data: native_alarm_for(
                data, "-unhealthy"
            ).update(
                {
                    "alarm_actions": [
                        "arn:aws:sns:us-east-2:111122223333:wrong-account"
                    ],
                    "ok_actions": ["arn:aws:sns:us-east-2:111122223333:wrong-account"],
                }
            ),
            "native alarm wrong same-account topic": lambda data: native_alarm_for(
                data, "-unhealthy"
            ).update(
                {
                    "alarm_actions": ["arn:aws:sns:us-east-2:767397897469:wrong-topic"],
                    "ok_actions": ["arn:aws:sns:us-east-2:767397897469:wrong-topic"],
                }
            ),
            "native alarm malformed NLB ARN": lambda data: data["native_nlb"].update(
                {"arn": "not-an-elbv2-arn"}
            ),
            "native canonical composite alarm": lambda data: data["native_alarms"][
                "composite_alarm_names"
            ].append("layerv-nhp-sandbox-relay-native-nlb-unhealthy"),
            "ASG missing native NHP target group": lambda data: data["canonical_asg"][
                "target_group_arns"
            ].remove(NATIVE_TG_ARN),
            "empty ASG and load balancer target groups": lambda data: (
                data["alb"].update({"target_group_arns": []}),
                data["native_nlb"].update({"target_group_arns": []}),
                data["canonical_asg"].update({"target_group_arns": []}),
            ),
        }
        expected_errors = {
            "public address": "public or IPv6 address",
            "undersized fleet": "desired instance count",
            "ASG member not InService": "not InService and Healthy",
            "EC2 instance stopped": "is not running",
            "legacy ASG remains": "orphaned pre-DMZ relay asgs remain",
            "orphan relay target group remains": "orphaned relay target groups remain",
            "rogue relay ENI": "do not map one-to-one",
            "untagged subnet": "unrecognized or missing Tier tag",
            "secondary IPv4 CIDR": "unexpected secondary IPv4 CIDR",
            "transitional IPv6 CIDR": "unexpected IPv6 CIDR",
            "second reverse-direction peer": "exactly one inventoried active main-VPC peer",
            "relay default route": "relay subnet subnet-relay-0 has a default route",
            "extra public route": "public subnet subnet-public-0 route table is not exactly local plus IGW default",
            "extra relay route": "relay subnet subnet-relay-0 route table is not exactly local, three peer /24s, and S3",
            "extra endpoint route": "endpoint subnet subnet-endpoint-0 route table is not local-only",
            "extra relay egress": "relay SG egress",
            "server broad UDP overlap": "server SG rules covering UDP 62206",
            "server all-protocol overlap": "server SG rules covering UDP 62206",
            "endpoint allow all": "interface endpoint ecr.api action set",
            "duplicate interface endpoint": "interface endpoint set differs from the exact required set",
            "endpoint unexpected write": "interface endpoint secretsmanager action set",
            "noncommercial secret ARN": "Secrets Manager endpoint is not scoped",
            "cross-account secret ARN": "Secrets Manager endpoint is not scoped",
            "duplicate GuardDuty endpoint": "guardduty-data must be a singleton",
            "GuardDuty policy extra statement": "guardduty-data policy",
            "incomplete endpoint deny": "account-boundary deny",
            "missing main return route": "main private subnet",
            "legacy main private table": "tagged extensible route tables",
            "missing main NAT default": "lacks exactly one active NAT default route",
            "public relay ENI": "relay-subnet network interface eni-relay-0 has a public or IPv6 address",
            "DNS fail open": "fail closed",
            "Resolver mutation protection": "mutation protection",
            "extra Resolver rule": "Resolver firewall rule set must contain exactly the reviewed",
            "advanced DNS override response": "exact HIGH-confidence NODATA blocks",
            "fractional advanced DNS priority": "exact HIGH-confidence NODATA blocks",
            "catch-all DNS override response": "priority-900 NODATA block",
            "fractional catch-all DNS priority": "priority-900 NODATA block",
            "wrong Resolver log destination": "query-log association",
            "different log KMS keys": "do not use the same customer KMS key",
            "broad log KMS context": "encryption context",
            "extra log KMS statement": "exactly account admin plus log delivery",
            "wrong flow log destination": "no healthy ALL-traffic CloudWatch VPC Flow Log",
            "target group HTTP": "target group is not HTTPS:8080",
            "target group wrong health": "target group is not HTTPS:8080",
            "missing WAF": "has no WAF association",
            "ALB deletion protection drift": "ALB deletion protection, WAF/HTTP hardening, or exact access-log destination",
            "ALB HTTP hardening drift": "ALB deletion protection, WAF/HTTP hardening, or exact access-log destination",
            "ALB XFF client port drift": "ALB deletion protection, WAF/HTTP hardening, or exact access-log destination",
            "ALB WAF fail-open drift": "ALB deletion protection, WAF/HTTP hardening, or exact access-log destination",
            "ALB log destination drift": "ALB deletion protection, WAF/HTTP hardening, or exact access-log destination",
            "ALB ownership tag drift": "ALB ownership tags are incomplete",
            "native NHP ack port exposed": "listener set is not exactly UDP 62206",
            "native NHP direct IP targets": "target group is not instance UDP:62206",
            "native NHP client IP lost": "target group is not instance UDP:62206",
            "native NHP liveness is not readiness": "/health/native-ready",
            "native NHP wrong listener target": "forwarding to its sole target group",
            "native NHP missing public subnet": "not in exactly the DMZ public subnets",
            "native NHP cross-zone off": "cross-zone or deletion-protection",
            "native NHP ownership tag missing": "ownership tags are incomplete",
            "native stable alias missing": "stable native NHP Route53 alias is missing",
            "native stable alias retargeted": "stable native NHP Route53 alias is missing",
            "native stable alias wrong zone": "stable native NHP Route53 alias is missing",
            "native stable hosted zone wrong": "stable native NHP Route53 alias is missing",
            "native stable alias health disabled": "stable native NHP Route53 alias is missing",
            "native stable alias weighted": "uses an unreviewed routing policy",
            "native stable alias address record": "uses an unreviewed routing policy",
            "native partial alarm missing": "alarm inventory must be exactly two metric alarms",
            "native partial alarm wrong metric": "partial-target-loss alarm",
            "native partial alarm wrong dimension": "partial-target-loss alarm",
            "native zero alarm missing": "alarm inventory must be exactly two metric alarms",
            "native zero alarm wrong missing policy": "zero-ready-target alarm",
            "native zero alarm actions disabled": "zero-ready-target alarm",
            "native alarm wrong unit": "partial-target-loss alarm",
            "native alarm duplicate dimension": "partial-target-loss alarm",
            "native alarm metric math": "partial-target-loss alarm",
            "native alarm cross-account action": "partial-target-loss alarm",
            "native alarm wrong same-account topic": "partial-target-loss alarm",
            "native alarm malformed NLB ARN": "partial-target-loss alarm",
            "native canonical composite alarm": "no composite alarms",
            "ASG missing native NHP target group": "not attached to exactly the HTTPS and native UDP target groups",
            "empty ASG and load balancer target groups": "not attached to exactly the HTTPS and native UDP target groups",
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)
                errors = checker.validate_snapshot(snapshot, "structural")
                self.assertTrue(
                    any(expected_errors[name] in error for error in errors), errors
                )

    def test_core_structural_fences_have_direct_negative_coverage(self) -> None:
        cases = (
            (
                "schema version",
                lambda data: data.update({"schema_version": 0}),
                f"snapshot schema_version must be {checker.SCHEMA_VERSION}",
            ),
            (
                "VPC CIDR",
                lambda data: data["vpc"].update({"cidr": "10.102.0.0/16"}),
                "relay DMZ VPC does not use the reviewed sandbox 10.101.0.0/16 CIDR",
            ),
            (
                "desired capacity floor",
                lambda data: data["canonical_asg"].update({"desired_capacity": 2}),
                "canonical relay ASG desired capacity must be at least three",
            ),
            (
                "empty relay ENI inventory",
                lambda data: data.update({"relay_network_interfaces": []}),
                "no relay-subnet network interfaces were inventoried",
            ),
            (
                "missing public main-VPC NHP listener inventory",
                lambda data: data["orphaned_legacy_resources"].pop(
                    "public_main_vpc_nhp_listeners"
                ),
                "public main-VPC NHP listener inventory is missing or malformed",
            ),
            (
                "ec2messages endpoint",
                lambda data: data["endpoints"].append(
                    {
                        **copy.deepcopy(data["endpoints"][0]),
                        "id": "vpce-ec2messages",
                        "service": "ec2messages",
                    }
                ),
                "ec2messages endpoint must not exist",
            ),
        )
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)
                self.assertIn(expected, checker.validate_structural(snapshot))

    def test_ssm_endpoint_reports_every_misscoped_action(self) -> None:
        snapshot = good_snapshot()
        endpoint = next(row for row in snapshot["endpoints"] if row["service"] == "ssm")
        endpoint["policy"]["Statement"][1]["Resource"] = (
            "arn:aws:ssm:us-east-2:767397897469:wrong"
        )
        errors = checker.validate_structural(snapshot)
        misscoped = [
            error
            for error in errors
            if error.startswith("SSM endpoint ")
            and error.endswith(" has an unexpected resource shape")
        ]
        self.assertEqual(
            len(checker.EXPECTED_ENDPOINT_ACTIONS["ssm"] - {"ssm:GetParameter"}),
            len(misscoped),
            errors,
        )

    def test_security_group_contract_mutations_fail_exactly(self) -> None:
        cases = {
            "non-singular identity": (
                lambda data: data["security_groups"]["relay_ids"].append(
                    "sg-relay-extra"
                ),
                "relay, ALB, native NHP NLB, endpoint, and server SG identities must each be singular",
            ),
            "relay ingress": (
                lambda data: data["security_groups"]["by_id"]["sg-relay"][
                    "inbound"
                ].pop(),
                "relay SG ingress differs from ALB:8080, native NHP NLB UDP:62206/health:8080, plus server:62207",
            ),
            "ALB ingress": (
                lambda data: data["security_groups"]["by_id"]["sg-alb"]["inbound"][
                    0
                ].update({"source": "10.0.0.0/8"}),
                "ALB SG ingress is not exactly public TCP 443",
            ),
            "ALB egress": (
                lambda data: data["security_groups"]["by_id"]["sg-alb"]["outbound"][
                    0
                ].update({"from": 443, "to": 443}),
                "ALB SG egress is not exactly relay TCP 8080",
            ),
            "native NHP public ACK ingress": (
                lambda data: data["security_groups"]["by_id"]["sg-native-nhp"][
                    "inbound"
                ][0].update({"from": 62207, "to": 62207}),
                "native NHP NLB SG ingress is not exactly public UDP 62206",
            ),
            "native NHP broad egress": (
                lambda data: data["security_groups"]["by_id"]["sg-native-nhp"][
                    "outbound"
                ][0].update({"source_type": "cidr_ipv4", "source": "0.0.0.0/0"}),
                "native NHP NLB SG egress is not exactly relay UDP 62206 plus HTTPS health TCP 8080",
            ),
            "endpoint ingress": (
                lambda data: data["security_groups"]["by_id"]["sg-endpoint"]["inbound"][
                    0
                ].update({"from": 80, "to": 80}),
                "endpoint SG ingress is not exactly relay TCP 443",
            ),
            "endpoint egress": (
                lambda data: data["security_groups"]["by_id"]["sg-endpoint"][
                    "outbound"
                ].append(rule("tcp", 443, 443, "cidr_ipv4", "0.0.0.0/0")),
                "endpoint SG must have no egress rules",
            ),
            "server UDP sources": (
                lambda data: data["security_groups"]["by_id"]["sg-server"][
                    "inbound"
                ].pop(),
                "server SG rules covering UDP 62206 are not exactly main VPC plus relay /24s",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)

                errors = checker.validate_snapshot(snapshot, "structural")

                self.assertIn(expected_error, errors)

    def test_missing_inventory_primary_errors_do_not_cascade(self) -> None:
        snapshot = good_snapshot()
        snapshot["native_dns"] = {"record_count": 0}
        errors = checker.validate_snapshot(snapshot, "structural")
        self.assertIn(
            "stable native NHP Route53 alias is missing or does not target the canonical NLB",
            errors,
        )
        self.assertNotIn(
            "stable native NHP Route53 alias uses an unreviewed routing policy",
            errors,
        )

        snapshot = good_snapshot()
        subnets_in_tier(snapshot, "public-alb")[0]["routes"][1].update(
            {"target_type": "nat", "target": "nat-bad"}
        )
        errors = checker.validate_snapshot(snapshot, "structural")
        self.assertIn(
            "public subnet subnet-public-0 lacks exactly one IGW default route",
            errors,
        )
        self.assertNotIn(
            "public subnet subnet-public-0 route table is not exactly local plus IGW default",
            errors,
        )

    def test_main_route_cardinality_is_independent_of_s3_association(self) -> None:
        snapshot = good_snapshot()
        for subnet in subnets_in_tier(snapshot, "isolated-relay"):
            subnet["routes"] = [
                route_row
                for route_row in subnet["routes"]
                if route_row.get("destination") != "10.100.12.0/24"
            ]
        endpoint_for(snapshot, "s3")["route_table_ids"].pop()

        errors = checker.validate_snapshot(snapshot, "structural")

        self.assertIn(
            "relay route tables must contain exactly three main-VPC /24 routes",
            errors,
        )
        self.assertIn(
            "S3 endpoint is not associated with exactly the relay route tables",
            errors,
        )

    def test_s3_endpoint_contract_mutations_fail_exactly(self) -> None:
        cases = {
            "route-table association": (
                lambda data: endpoint_for(data, "s3")["route_table_ids"].pop(),
                "S3 endpoint is not associated with exactly the relay route tables",
            ),
            "policy action": (
                lambda data: endpoint_for(data, "s3")["policy"]["Statement"][0].update(
                    {"Action": "s3:ListBucket"}
                ),
                "S3 endpoint policy exceeds or omits the five-resource GetObject contract",
            ),
            "policy resource": (
                lambda data: endpoint_for(data, "s3")["policy"]["Statement"][0][
                    "Resource"
                ].pop(),
                "S3 endpoint policy exceeds or omits the five-resource GetObject contract",
            ),
            "relay prefix-list route": (
                lambda data: subnets_in_tier(data, "isolated-relay")[0]["routes"].pop(),
                "relay subnet subnet-relay-0 lacks exactly one S3 endpoint prefix-list route",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)

                errors = checker.validate_snapshot(snapshot, "structural")

                self.assertIn(expected_error, errors)

    def test_alb_listener_contract_mutations_fail_exactly(self) -> None:
        cases = {
            "TLS policy": (
                lambda data: data["alb"]["listeners"][0].update(
                    {"ssl_policy": "ELBSecurityPolicy-TLS-1-0-2015-04"}
                ),
                "canonical relay ALB listener set is not exactly HTTPS 443",
            ),
            "listener cardinality": (
                lambda data: data["alb"]["listeners"].append(
                    copy.deepcopy(data["alb"]["listeners"][0])
                ),
                "canonical relay ALB listener set is not exactly HTTPS 443",
            ),
            "default action": (
                lambda data: data["alb"]["listeners"][0]["rules"][0]["actions"][
                    0
                ].update({"Type": "redirect"}),
                "canonical relay ALB default action is not one fixed response",
            ),
            "forwarding conditions": (
                lambda data: data["alb"]["listeners"][0]["rules"][1]["conditions"][
                    1
                ].update({"Values": ["GET"]}),
                "canonical relay ALB forwarding rule is not POST/OPTIONS /relay/*",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)

                errors = checker.validate_snapshot(snapshot, "structural")

                self.assertIn(expected_error, errors)

    def test_endpoint_resource_scope_mutations_fail_exactly(self) -> None:
        cases = {
            "logs": (
                lambda data: endpoint_for(data, "logs")["policy"]["Statement"][
                    0
                ].update({"Resource": "*"}),
                "Logs endpoint is not scoped to the relay log group",
            ),
            "ecr.api repository": (
                lambda data: endpoint_for(data, "ecr.api")["policy"]["Statement"][
                    1
                ].update({"Resource": "*"}),
                "ecr.api endpoint is not scoped to the relay repository",
            ),
            "ecr.dkr repository": (
                lambda data: endpoint_for(data, "ecr.dkr")["policy"]["Statement"][
                    0
                ].update({"Resource": "*"}),
                "ecr.dkr endpoint is not scoped to the relay repository",
            ),
            "ecr.api token": (
                lambda data: endpoint_for(data, "ecr.api")["policy"]["Statement"][
                    0
                ].update(
                    {
                        "Resource": "arn:aws:ecr:us-east-2:767397897469:repository/layerv-nhp-sandbox-relay"
                    }
                ),
                "ecr.api authorization-token action must use Resource *",
            ),
            "SSM image parameter": (
                lambda data: endpoint_for(data, "ssm")["policy"]["Statement"][0].update(
                    {"Resource": "*"}
                ),
                "SSM endpoint GetParameter is not scoped to the relay image pin",
            ),
            "monitoring namespace": (
                lambda data: endpoint_for(data, "monitoring")["policy"]["Statement"][0][
                    "Condition"
                ]["StringEquals"].update({"cloudwatch:namespace": "Other"}),
                "Monitoring endpoint is not scoped to the LayerV/NHP namespace",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)

                errors = checker.validate_snapshot(snapshot, "structural")

                self.assertIn(expected_error, errors)

    def test_subnet_route_table_cardinality_mutations_fail_exactly(self) -> None:
        cases = {
            "total subnet count": (
                lambda data: data["subnets"].pop(),
                "DMZ must contain exactly nine subnets (found 8)",
            ),
            "tier subnet count": (
                lambda data: data["subnets"][-1].update({"tier": "public-alb"}),
                "DMZ must have exactly three public-alb subnets (found 4)",
            ),
            "public route-table sharing": (
                lambda data: subnets_in_tier(data, "public-alb")[0].update(
                    {"route_table_id": "rtb-public-extra"}
                ),
                "public ALB subnets must share exactly one public route table",
            ),
            "relay route-table cardinality": (
                lambda data: subnets_in_tier(data, "isolated-relay")[1].update(
                    {
                        "route_table_id": subnets_in_tier(data, "isolated-relay")[0][
                            "route_table_id"
                        ]
                    }
                ),
                "relay subnets must use three distinct relay route tables",
            ),
            "endpoint route-table cardinality": (
                lambda data: subnets_in_tier(data, "isolated-endpoint")[1].update(
                    {
                        "route_table_id": subnets_in_tier(data, "isolated-endpoint")[0][
                            "route_table_id"
                        ]
                    }
                ),
                "endpoint subnets must use three distinct local-only route tables",
            ),
            "relay-endpoint route-table sharing": (
                lambda data: subnets_in_tier(data, "isolated-endpoint")[0].update(
                    {
                        "route_table_id": subnets_in_tier(data, "isolated-relay")[0][
                            "route_table_id"
                        ]
                    }
                ),
                "relay and endpoint subnets share a route table",
            ),
            "map public IP": (
                lambda data: subnets_in_tier(data, "isolated-relay")[0].update(
                    {"map_public_ip_on_launch": True}
                ),
                "isolated-relay subnets must disable map_public_ip_on_launch",
            ),
            "subnet CIDR": (
                lambda data: subnets_in_tier(data, "isolated-endpoint")[0].update(
                    {"cidr": "10.101.99.0/24"}
                ),
                "isolated-endpoint subnet CIDRs differ from the reviewed contract",
            ),
            "public IGW default": (
                lambda data: subnets_in_tier(data, "public-alb")[0]["routes"][1].update(
                    {"target_type": "nat", "target": "nat-bad"}
                ),
                "public subnet subnet-public-0 lacks exactly one IGW default route",
            ),
            "public route exactness": (
                lambda data: subnets_in_tier(data, "public-alb")[0]["routes"].append(
                    route("192.0.2.0/24", "gateway", "igw-dmz")
                ),
                "public subnet subnet-public-0 route table is not exactly local plus IGW default",
            ),
            "relay route exactness": (
                lambda data: subnets_in_tier(data, "isolated-relay")[0][
                    "routes"
                ].append(route("192.0.2.0/24", "network_interface", "eni-bad")),
                "relay subnet subnet-relay-0 route table is not exactly local, three peer /24s, and S3",
            ),
            "endpoint local-only route": (
                lambda data: subnets_in_tier(data, "isolated-endpoint")[0][
                    "routes"
                ].append(route("192.0.2.0/24", "peering", "pcx-bad")),
                "endpoint subnet subnet-endpoint-0 route table is not local-only",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)

                errors = checker.validate_snapshot(snapshot, "structural")

                self.assertIn(expected_error, errors)

    def test_interface_endpoint_health_mutations_fail_exactly(self) -> None:
        cases = {
            "state": (
                lambda data: endpoint_for(data, "ecr.api").update({"state": "pending"}),
                "interface endpoint vpce-ecr-api is not available",
            ),
            "private DNS": (
                lambda data: endpoint_for(data, "ecr.api").update(
                    {"private_dns_enabled": False}
                ),
                "interface endpoint vpce-ecr-api lacks private DNS",
            ),
            "security group": (
                lambda data: endpoint_for(data, "ecr.api").update(
                    {"security_group_ids": ["sg-wrong"]}
                ),
                "interface endpoint vpce-ecr-api is not in the one endpoint SG",
            ),
            "endpoint subnet": (
                lambda data: endpoint_for(data, "ecr.api")["subnet_ids"].pop(),
                "interface endpoint vpce-ecr-api is not in all endpoint subnets",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)

                errors = checker.validate_snapshot(snapshot, "structural")

                self.assertIn(expected_error, errors)

    def test_peering_dns_and_flow_log_mutations_fail_exactly(self) -> None:
        cases = {
            "DMZ-to-main DNS": lambda data: data["peer"].update(
                {"dmz_dns_resolution": False}
            ),
            "main-to-DMZ DNS": lambda data: data["peer"].update(
                {"main_dns_resolution": False}
            ),
            "traffic type": lambda data: data["flow_logs"][0].update(
                {"traffic_type": "REJECT"}
            ),
            "status": lambda data: data["flow_logs"][0].update(
                {"flow_log_status": "INACTIVE"}
            ),
            "delivery": lambda data: data["flow_logs"][0].update(
                {"delivery_status": "FAILED"}
            ),
            "destination type": lambda data: data["flow_logs"][0].update(
                {"destination_type": "s3"}
            ),
            "aggregation": lambda data: data["flow_logs"][0].update(
                {"max_aggregation_interval": 600}
            ),
            "log format": lambda data: data["flow_logs"][0].update(
                {"log_format": "${srcaddr} ${dstaddr}"}
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)

                errors = checker.validate_snapshot(snapshot, "structural")

                expected_error = (
                    "VPC peering DNS resolution is not enabled in both directions"
                    if "DNS" in name
                    else "DMZ has no healthy ALL-traffic CloudWatch VPC Flow Log"
                )
                self.assertIn(expected_error, errors)

    def test_functional_mutations_fail_closed(self) -> None:
        cases = {
            "unhealthy target": lambda data: data["functional"]["target_health"][
                0
            ].update({"state": "unhealthy"}),
            "old SSM Agent": lambda data: data["functional"]["ssm"][0].update(
                {"agent_version": "3.2.1.0"}
            ),
            "SSM Offline": lambda data: data["functional"]["ssm"][0].update(
                {"ping_status": "ConnectionLost"}
            ),
            "unhealthy GuardDuty": lambda data: data["functional"][
                "guardduty_coverage"
            ][0].update({"status": "UNHEALTHY"}),
            "missing account detector": lambda data: data["functional"].update(
                {"guardduty_detector_count": 0, "guardduty_coverage": []}
            ),
            "multiple account detectors": lambda data: data["functional"].update(
                {"guardduty_detector_count": 2}
            ),
            "missing SSM row": lambda data: data["functional"]["ssm"].pop(0),
            "missing GuardDuty row": lambda data: data["functional"][
                "guardduty_coverage"
            ].pop(0),
            "missing probe row": lambda data: data["functional"]["probes"].pop(0),
            "public DNS resolves": lambda data: data["functional"]["probes"][0].update(
                {"blocked_public_dns": False}
            ),
            "approved DNS fails": lambda data: data["functional"]["probes"][0].update(
                {"allowed_dns": False}
            ),
            "direct public route": lambda data: data["functional"]["probes"][0].update(
                {"public_tcp_unreachable": False}
            ),
            "relay stopped": lambda data: data["functional"]["probes"][0].update(
                {"relay_active": False}
            ),
            "probe failed": lambda data: data["functional"]["probes"][0].update(
                {"status": "Failed"}
            ),
            "native alarm breached": lambda data: native_alarm_for(
                data, "-unhealthy"
            ).update({"state_value": "ALARM"}),
            "native alarm insufficient data": lambda data: native_alarm_for(
                data, "-zero-healthy"
            ).update({"state_value": "INSUFFICIENT_DATA"}),
        }
        expected_errors = {
            "unhealthy target": "target group tg-arn does not show every canonical relay instance healthy",
            "old SSM Agent": "relay instance i-relay-0 has SSM Agent below 3.3.40.0",
            "SSM Offline": "relay instance i-relay-0 is not SSM Online",
            "unhealthy GuardDuty": "relay instance i-relay-0 lacks healthy GuardDuty runtime coverage",
            "missing account detector": "AWS account must have exactly one GuardDuty detector (found 0)",
            "multiple account detectors": "AWS account must have exactly one GuardDuty detector (found 2)",
            "missing SSM row": "relay instance i-relay-0 is not SSM Online",
            "missing GuardDuty row": "relay instance i-relay-0 lacks healthy GuardDuty runtime coverage",
            "missing probe row": "relay instance i-relay-0 SSM boundary probe did not succeed",
            "public DNS resolves": "relay instance i-relay-0 resolved a non-allowlisted public domain",
            "approved DNS fails": "relay instance i-relay-0 cannot resolve every approved AWS endpoint",
            "direct public route": "relay instance i-relay-0 can reach representative public TCP 443 canary",
            "relay stopped": "relay instance i-relay-0 does not have an active relay service",
            "probe failed": "relay instance i-relay-0 SSM boundary probe did not succeed",
            "native alarm breached": "native NHP partial-loss and zero-ready-target alarms must both be in OK state",
            "native alarm insufficient data": "native NHP partial-loss and zero-ready-target alarms must both be in OK state",
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                snapshot = good_snapshot()
                mutate(snapshot)
                errors = checker.validate_snapshot(snapshot, "functional")
                self.assertIn(expected_errors[name], errors)

        snapshot = good_snapshot()
        snapshot["functional"].update(
            {"guardduty_detector_count": 0, "guardduty_coverage": []}
        )
        errors = checker.validate_snapshot(snapshot, "functional")
        self.assertFalse(
            any("relay instance" in error and "GuardDuty" in error for error in errors),
            errors,
        )

    def test_functional_empty_instance_set_fails_independently(self) -> None:
        snapshot = good_snapshot()
        snapshot["canonical_asg"]["instance_ids"] = []
        snapshot["functional"] = {
            "target_health": [],
            "ssm": [],
            "guardduty_detector_count": 1,
            "guardduty_coverage": [],
            "probes": [],
        }
        with mock.patch.object(checker, "validate_structural", return_value=[]):
            errors = checker.validate_functional(snapshot)

        self.assertEqual(
            [
                "functional relay boundary validation requires at least one canonical instance"
            ],
            errors,
        )

    def test_native_alarm_state_is_a_functional_gate(self) -> None:
        snapshot = good_snapshot()
        native_alarm_for(snapshot, "-unhealthy")["state_value"] = "ALARM"

        self.assertEqual([], checker.validate_snapshot(snapshot, "structural"))
        self.assertIn(
            "native NHP partial-loss and zero-ready-target alarms must both be in OK state",
            checker.validate_snapshot(snapshot, "functional"),
        )

    def test_native_udp_target_health_must_cover_entire_relay_fleet(self) -> None:
        snapshot = good_snapshot()
        native_row = next(
            row
            for row in snapshot["functional"]["target_health"]
            if row["target_group_arn"] == NATIVE_TG_ARN
        )
        native_row["state"] = "unhealthy"
        errors = checker.validate_snapshot(snapshot, "functional")
        self.assertIn(
            f"target group {NATIVE_TG_ARN} does not show every canonical relay instance healthy",
            errors,
        )

    def test_bare_major_ssm_version_fails_closed(self) -> None:
        self.assertEqual((), checker._version("3"))
        self.assertEqual((), checker._version("v3.3.40.0"))
        self.assertEqual((), checker._version("3.3.40.0-build"))
        self.assertEqual((3, 3, 40, 0), checker._version(" 3.3.40.0 "))
        snapshot = good_snapshot()
        snapshot["functional"]["ssm"][0]["agent_version"] = "3"
        errors = checker.validate_snapshot(snapshot, "functional")
        self.assertTrue(any("SSM Agent below 3.3.40.0" in error for error in errors))

    def test_exact_nonnegative_int_never_truncates_or_accepts_aliases(self) -> None:
        self.assertEqual(100, checker._exact_nonnegative_int(100))
        self.assertEqual(100, checker._exact_nonnegative_int("100"))
        for value in (100.9, True, -1, "0100", "+100", "100.0", " 100 "):
            with self.subTest(value=value):
                self.assertIsNone(checker._exact_nonnegative_int(value))

    def test_ssm_minimum_version_message_is_derived_from_contract(self) -> None:
        snapshot = good_snapshot()
        snapshot["functional"]["ssm"][0]["agent_version"] = "1.0.0"
        expected = ".".join(str(part) for part in checker.MIN_SSM_AGENT_VERSION)

        errors = checker.validate_snapshot(snapshot, "functional")

        self.assertTrue(any(f"SSM Agent below {expected}" in error for error in errors))

    def test_snapshot_environment_mismatch_is_operational_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(good_snapshot()))
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT_PATH),
                    "--environment",
                    "prod",
                    "--mode",
                    "structural",
                    "--snapshot",
                    str(path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, result.returncode)
        self.assertIn("does not match", result.stderr)

    def test_snapshot_wait_is_one_shot(self) -> None:
        snapshot = good_snapshot()
        snapshot["instances"][0]["public_ip"] = "203.0.113.9"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(snapshot))
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT_PATH),
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--snapshot",
                    str(path),
                    "--wait-seconds",
                    "300",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=2,
            )
        self.assertEqual(1, result.returncode)

    def test_live_wait_retries_violations_until_clean(self) -> None:
        converging = good_snapshot()
        converging["instances"][0]["public_ip"] = "203.0.113.9"
        output = io.StringIO()
        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker,
                "collect_structural",
                side_effect=[converging, good_snapshot()],
            ) as collect,
            mock.patch.object(checker.time, "monotonic", side_effect=[0.0, 1.0]),
            mock.patch.object(checker.time, "sleep") as sleep,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(
                [
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--wait-seconds",
                    "30",
                ]
            )
        self.assertEqual(0, result)
        self.assertEqual(2, collect.call_count)
        sleep.assert_called_once()

    def test_live_wait_deadline_exhaustion_returns_violation_exit_one(self) -> None:
        snapshot = good_snapshot()
        snapshot["instances"][0]["public_ip"] = "203.0.113.9"
        output = io.StringIO()
        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker, "collect_structural", return_value=snapshot
            ) as collect,
            mock.patch.object(
                checker, "_sleep_until_retry", return_value=False
            ) as retry,
            mock.patch.object(checker.time, "monotonic", return_value=0.0),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(
                [
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--wait-seconds",
                    "30",
                ]
            )

        self.assertEqual(1, result)
        self.assertEqual(1, collect.call_count)
        retry.assert_called_once()
        self.assertIn("public or IPv6 address", output.getvalue())

    def test_missing_region_is_inventory_exit_two(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(
                checker,
                "AwsCli",
                side_effect=checker.InventoryError("AWS region is not configured"),
            ),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(["--environment", "sandbox", "--mode", "structural"])

        self.assertEqual(2, result)
        self.assertIn("AWS region is not configured", output.getvalue())

    def test_wrong_environment_region_fails_before_inventory_calls(self) -> None:
        output = io.StringIO()
        aws = mock.Mock(region="us-west-2")
        with (
            mock.patch.object(checker, "AwsCli", return_value=aws),
            mock.patch.object(checker, "collect_structural") as collect,
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(["--environment", "sandbox", "--mode", "structural"])

        self.assertEqual(2, result)
        self.assertIn("requires AWS region 'us-east-2'", output.getvalue())
        collect.assert_not_called()

    def test_retry_backoff_is_exponential_and_bounded(self) -> None:
        self.assertEqual(
            [5.0, 10.0, 20.0, 30.0, 30.0, 30.0],
            [checker._retry_delay_seconds(attempt) for attempt in range(6)],
        )

    def test_live_functional_retries_share_successful_probe_cache(self) -> None:
        snapshots = [good_snapshot(), good_snapshot(), good_snapshot()]
        cache_objects = []
        output = io.StringIO()

        def collect_functional(snapshot: dict, aws: object, cache: dict) -> bool:
            cache_objects.append(cache)
            used_cache = bool(cache)
            if not cache:
                cache["i-relay-0"] = {
                    "instance_id": "i-relay-0",
                    "status": "Success",
                    "allowed_dns": True,
                    "blocked_public_dns": True,
                    "public_tcp_unreachable": True,
                    "relay_active": True,
                }
            snapshot["functional"] = copy.deepcopy(good_snapshot()["functional"])
            return used_cache

        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker, "collect_structural", side_effect=snapshots
            ) as collect,
            mock.patch.object(
                checker, "collect_functional", side_effect=collect_functional
            ),
            mock.patch.object(
                checker, "validate_snapshot", side_effect=[["converging"], [], []]
            ),
            mock.patch.object(checker.time, "monotonic", side_effect=[0.0, 1.0]),
            mock.patch.object(checker.time, "sleep") as sleep,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(
                [
                    "--environment",
                    "sandbox",
                    "--mode",
                    "functional",
                    "--wait-seconds",
                    "30",
                ]
            )

        self.assertEqual(0, result)
        self.assertEqual(3, collect.call_count)
        self.assertIs(cache_objects[0], cache_objects[1])
        self.assertIs(cache_objects[1], cache_objects[2])
        self.assertIn("i-relay-0", cache_objects[2])
        self.assertIn("final fresh all-instance confirmation", output.getvalue())
        sleep.assert_called_once()

    def test_final_fresh_probe_catches_mid_run_service_regression(self) -> None:
        snapshots = [good_snapshot(), good_snapshot()]
        output = io.StringIO()
        collection_count = 0

        def collect_functional(snapshot: dict, aws: object, cache: dict) -> bool:
            nonlocal collection_count
            snapshot["functional"] = copy.deepcopy(good_snapshot()["functional"])
            used_cache = collection_count == 0
            if collection_count == 1:
                snapshot["functional"]["probes"][0]["relay_active"] = False
            collection_count += 1
            return used_cache

        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(checker, "collect_structural", side_effect=snapshots),
            mock.patch.object(
                checker, "collect_functional", side_effect=collect_functional
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(["--environment", "sandbox", "--mode", "functional"])

        self.assertEqual(1, result)
        self.assertEqual(2, collection_count)
        self.assertIn("does not have an active relay service", output.getvalue())

    def test_final_fresh_confirmation_rejects_cached_probe_reuse(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker,
                "collect_structural",
                side_effect=[good_snapshot(), good_snapshot()],
            ),
            mock.patch.object(checker, "collect_functional", return_value=True),
            mock.patch.object(checker, "validate_snapshot", return_value=[]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(["--environment", "sandbox", "--mode", "functional"])

        self.assertEqual(2, result)
        self.assertIn(
            "final fresh functional confirmation unexpectedly reused cached probes",
            output.getvalue(),
        )

    def test_final_fresh_confirmation_clears_partial_cache_before_retry(self) -> None:
        output = io.StringIO()
        calls = 0
        retry_saw_empty_cache = False

        def collect_functional(snapshot: dict, aws: object, cache: dict) -> bool:
            nonlocal calls, retry_saw_empty_cache
            snapshot["functional"] = copy.deepcopy(good_snapshot()["functional"])
            if calls == 0:
                calls += 1
                return True
            if calls == 1:
                calls += 1
                cache["i-partial"] = {"status": "Success"}
                raise checker.RetryableInventoryError("InvalidInstanceId")
            retry_saw_empty_cache = not cache
            calls += 1
            return False

        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker,
                "collect_structural",
                side_effect=[good_snapshot(), good_snapshot(), good_snapshot()],
            ),
            mock.patch.object(
                checker, "collect_functional", side_effect=collect_functional
            ),
            mock.patch.object(checker, "validate_snapshot", return_value=[]),
            mock.patch.object(
                checker, "_sleep_until_retry", return_value=True
            ) as sleep,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(
                [
                    "--environment",
                    "sandbox",
                    "--mode",
                    "functional",
                    "--wait-seconds",
                    "30",
                ]
            )

        self.assertEqual(0, result)
        self.assertEqual(3, calls)
        self.assertTrue(retry_saw_empty_cache)
        sleep.assert_called_once()

    def test_live_wait_retries_only_named_operational_transients(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker,
                "collect_structural",
                side_effect=[
                    checker.RetryableInventoryError(
                        "relay DMZ VPC has no active peers"
                    ),
                    good_snapshot(),
                ],
            ) as collect,
            mock.patch.object(checker.time, "monotonic", side_effect=[0.0, 1.0]),
            mock.patch.object(checker.time, "sleep") as sleep,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(
                [
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--wait-seconds",
                    "30",
                ]
            )
        self.assertEqual(0, result)
        self.assertEqual(2, collect.call_count)
        sleep.assert_called_once()

        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker,
                "collect_structural",
                side_effect=checker.InventoryError("AccessDeniedException"),
            ) as collect,
            mock.patch.object(checker.time, "monotonic", return_value=0.0),
            mock.patch.object(checker.time, "sleep") as sleep,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(
                [
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--wait-seconds",
                    "30",
                ]
            )
        self.assertEqual(2, result)
        self.assertEqual(1, collect.call_count)
        sleep.assert_not_called()
        self.assertFalse(
            checker._retryable_inventory_error(
                checker.InventoryError("relay DMZ VPC has 0 active peers")
            )
        )

    def test_ec2_and_ssm_instance_not_found_spellings_are_retryable(self) -> None:
        for error_code in ("InvalidInstanceID.NotFound", "InvalidInstanceId"):
            with self.subTest(error_code=error_code):
                self.assertTrue(
                    checker._retryable_inventory_error(
                        checker.InventoryError(f"AWS CLI failed: {error_code}")
                    )
                )

    def test_unexpected_collector_exception_is_exit_two_without_traceback(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(
                checker, "AwsCli", return_value=mock.Mock(region="us-east-2")
            ),
            mock.patch.object(
                checker,
                "collect_structural",
                # Even if an unexpected exception's text contains one of the
                # named convergence patterns, its type makes it non-retryable.
                side_effect=IndexError("relay DMZ VPC has 0 active peers"),
            ),
            mock.patch.object(checker.time, "sleep") as sleep,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = checker.main(
                [
                    "--environment",
                    "sandbox",
                    "--mode",
                    "structural",
                    "--wait-seconds",
                    "30",
                ]
            )

        self.assertEqual(2, result)
        self.assertIn(
            "unexpected collector failure (IndexError): relay DMZ VPC has 0 active peers",
            output.getvalue(),
        )
        self.assertNotIn("Traceback", output.getvalue())
        sleep.assert_not_called()


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    minimum_expected_tests = 79
    discovered = suite.countTestCases()
    if discovered < minimum_expected_tests:
        raise SystemExit(
            f"refusing vacuous detector test run: discovered {discovered}, "
            f"expected at least {minimum_expected_tests}"
        )
    result = unittest.TextTestRunner().run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)

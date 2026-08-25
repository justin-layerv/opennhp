#!/usr/bin/env python3
"""Stable-read the exact delivered sandbox runtime used by fixed canaries."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

ACCOUNT = "767397897469"
REGION = "us-east-2"
SESSION_TABLE = "layerv-nhp-sandbox-cell0-nhp-session-control"
AGENT_TABLE = "layerv-nhp-sandbox-control-qurl-agent-keys"
CATALOG_TABLE = "layerv-nhp-sandbox-control-connector-authority"
RETIRED_AGENT_TABLE = "layerv-nhp-sandbox-cell0-qurl-agent-keys"
QURL_SERVICE_RUNTIME = "layerv-nhp-sandbox-cell0-qurl-api"
SOURCE_ROOT = Path(__file__).resolve().parents[2]
CONTROL_VARIABLES = SOURCE_ROOT / "terraform/control/environments/sandbox/variables.tf"
SANDBOX_TFVARS = SOURCE_ROOT / "terraform/environments/sandbox/terraform.tfvars"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

PARAMETERS = (
    "/sandbox/nhp/server/active-color",
    "/sandbox/nhp/server/asg-name",
    "/sandbox/nhp/server/green-asg-name",
    "/sandbox/nhp/server/image-tag",
    "/sandbox/nhp/server/green-image-tag",
    "/sandbox/nhp/ac/active-color",
    "/sandbox/nhp/ac/asg-name",
    "/sandbox/nhp/ac/green-asg-name",
    "/sandbox/nhp/ac/image-tag",
    "/sandbox/nhp/ac/green-image-tag",
    "/sandbox/nhp/relay/asg-name",
    "/sandbox/nhp/relay/image-tag",
    "/sandbox/nhp/control/hub/identity/public-key",
    "/sandbox/nhp/qurl/qv2-issuer-key",
    "/sandbox/nhp/customer-journey/fixed-canary-v1",
    "/layerv-nhp-sandbox/qurl-ecs-cluster",
    "/layerv-nhp-sandbox/qurl-ecs-service",
)
ASGS = {
    "server_blue": "layerv-nhp-sandbox-server",
    "server_green": "layerv-nhp-sandbox-server-green",
    "ac_blue": "layerv-nhp-sandbox-ac",
    "ac_green": "layerv-nhp-sandbox-ac-green",
    "relay": "layerv-nhp-sandbox-relay-dmz",
}
IMAGE_RUNTIME = {
    "server_blue": ("layerv/nhp-server", "/sandbox/nhp/server/image-tag"),
    "server_green": ("layerv/nhp-server", "/sandbox/nhp/server/green-image-tag"),
    "ac_blue": ("layerv/nhp-ac", "/sandbox/nhp/ac/image-tag"),
    "ac_green": ("layerv/nhp-ac", "/sandbox/nhp/ac/green-image-tag"),
    "relay": ("layerv/nhp-relay", "/sandbox/nhp/relay/image-tag"),
}


def _source_contract() -> dict[str, Any]:
    """Read the checked-out sandbox catalog and customer endpoint authority."""
    try:
        control = CONTROL_VARIABLES.read_text(encoding="utf-8")
        sandbox = SANDBOX_TFVARS.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeErrorExact("sandbox source authority is unavailable") from error
    block_match = re.search(r"(?ms)^  default = \{\n    cell0 = \{\n(?P<body>.*?)^    \}\n    cell1 = \{", control)
    if block_match is None:
        raise RuntimeErrorExact("sandbox cell0 source authority is not exact")
    body = block_match.group("body")

    def quoted(name: str) -> str:
        values = re.findall(rf'^      {re.escape(name)}\s+=\s+"([^"]+)"$', body, re.MULTILINE)
        if len(values) != 1:
            raise RuntimeErrorExact("sandbox cell0 source field is not exact")
        return values[0]

    def integer(name: str) -> int:
        values = re.findall(rf"^      {re.escape(name)}\s+=\s+([0-9]+)$", body, re.MULTILINE)
        if len(values) != 1:
            raise RuntimeErrorExact("sandbox cell0 source field is not exact")
        return int(values[0])

    source = {
        "cell_id": quoted("cell_id"),
        "status": quoted("status"),
        "endpoint_revision": integer("endpoint_revision"),
        "host": quoted("nhp_host"),
        "port": integer("nhp_port"),
        "server_public_key_b64": quoted("server_public_key_b64"),
        "selection_weight": quoted("selection_weight"),
        "updated_at": quoted("updated_at"),
    }
    tfvars = {}
    for name in ("qurl_v2_issuer_kid", "qurl_v2_relay_allowlist"):
        values = re.findall(rf'^{name}\s+=\s+"([^"]+)"$', sandbox, re.MULTILINE)
        if len(values) != 1:
            raise RuntimeErrorExact("sandbox customer endpoint source field is not exact")
        tfvars[name] = values[0]
    if (
        source["cell_id"] != "cell0"
        or source["status"] != "active"
        or source["port"] != 443
        or source["endpoint_revision"] <= 0
        or tfvars["qurl_v2_relay_allowlist"] != "relay.qurl.link.layerv.xyz"
    ):
        raise RuntimeErrorExact("sandbox source authority is outside the reviewed contract")
    return {"cell": source, "issuer_kid": tfvars["qurl_v2_issuer_kid"], "relay_hostname": tfvars["qurl_v2_relay_allowlist"]}


class RuntimeErrorExact(RuntimeError):
    """The delivered runtime is not one stable reviewed sandbox authority."""


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeErrorExact("runtime JSON has a duplicate key")
        result[key] = value
    return result


def _parameters(client: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for offset in range(0, len(PARAMETERS), 10):
        response = client.get_parameters(Names=list(PARAMETERS[offset : offset + 10]), WithDecryption=False)
        if set(response) - {"Parameters", "InvalidParameters", "ResponseMetadata"} or response.get("InvalidParameters"):
            raise RuntimeErrorExact("sandbox SSM parameter inventory is incomplete")
        for item in response.get("Parameters", []):
            if set(item) - {"ARN", "DataType", "LastModifiedDate", "Name", "Selector", "SourceResult", "Type", "Value", "Version"}:
                raise RuntimeErrorExact("sandbox SSM parameter shape drifted")
            name, value, version = item.get("Name"), item.get("Value"), item.get("Version")
            modified = item.get("LastModifiedDate")
            if (
                name in result
                or name not in PARAMETERS
                or not isinstance(value, str)
                or type(version) is not int
                or version <= 0
                or not isinstance(modified, dt.datetime)
                or modified.tzinfo is None
            ):
                raise RuntimeErrorExact("sandbox SSM parameter value is invalid")
            result[name] = {
                "value": value,
                "version": version,
                "last_modified_ms": int(modified.timestamp() * 1000),
            }
    if set(result) != set(PARAMETERS):
        raise RuntimeErrorExact("sandbox SSM parameter set is not exact")
    return result


def _parameter_values(snapshot: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {name: item["value"] for name, item in snapshot.items()}


def _image(ecr: Any, repository: str, slot: str) -> dict[str, str]:
    match = re.fullmatch(r"([0-9a-f]{40})(?:@(sha256:[0-9a-f]{64}))?", slot)
    if match is None:
        raise RuntimeErrorExact("sandbox image source tag is not exact")
    source, pinned_digest = match.groups()
    response = ecr.describe_images(repositoryName=repository, imageIds=[{"imageTag": source}])
    details = response.get("imageDetails", [])
    if len(details) != 1 or set(details[0]) - {"artifactMediaType", "imageDigest", "imageManifestMediaType", "imagePushedAt", "imageScanFindingsSummary", "imageScanStatus", "imageSizeInBytes", "imageTags", "lastRecordedPullTime", "registryId", "repositoryName"}:
        raise RuntimeErrorExact("sandbox ECR image inventory is not exact")
    digest = details[0].get("imageDigest")
    tags = details[0].get("imageTags", [])
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None or tags.count(source) != 1:
        raise RuntimeErrorExact("sandbox ECR source and digest do not agree")
    if pinned_digest is not None and pinned_digest != digest:
        raise RuntimeErrorExact("sandbox digest-qualified slot differs from ECR")
    return {"source_sha": source, "image_digest": digest}


def _launch_template(asg: dict[str, Any]) -> tuple[str, str]:
    if asg.get("MixedInstancesPolicy") is not None:
        raise RuntimeErrorExact("sandbox customer ASG uses an unreviewed mixed instances policy")
    template = asg.get("LaunchTemplate")
    if not isinstance(template, dict) or set(template) != {"LaunchTemplateId", "LaunchTemplateName", "Version"}:
        raise RuntimeErrorExact("sandbox customer ASG launch template is not exact")
    template_id, version = template["LaunchTemplateId"], template["Version"]
    if not isinstance(template_id, str) or not template_id.startswith("lt-") or not isinstance(version, str) or not version:
        raise RuntimeErrorExact("sandbox customer ASG launch template identity is invalid")
    return template_id, version


def _instance_projection(ec2: Any, instance_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not instance_ids:
        return {}
    response = ec2.describe_instances(InstanceIds=instance_ids)
    if response.get("NextToken"):
        raise RuntimeErrorExact("sandbox customer instance inventory is paginated")
    instances = [instance for reservation in response.get("Reservations", []) for instance in reservation.get("Instances", [])]
    by_id = {instance.get("InstanceId"): instance for instance in instances}
    if len(instances) != len(instance_ids) or set(by_id) != set(instance_ids):
        raise RuntimeErrorExact("sandbox customer instance inventory is not exact")
    return by_id


def _asgs(
    asg_client: Any,
    ec2: Any,
    active_server: str,
    active_ac: str,
    images: dict[str, dict[str, str]],
    parameters: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=list(ASGS.values()))
    groups = response.get("AutoScalingGroups", [])
    if len(groups) != len(ASGS) or response.get("NextToken"):
        raise RuntimeErrorExact("sandbox customer ASG inventory is not exact")
    by_name = {item.get("AutoScalingGroupName"): item for item in groups}
    if set(by_name) != set(ASGS.values()):
        raise RuntimeErrorExact("sandbox customer ASG names drifted")
    result: dict[str, Any] = {}
    for label, name in ASGS.items():
        group = by_name[name]
        desired, minimum, maximum = group.get("DesiredCapacity"), group.get("MinSize"), group.get("MaxSize")
        if any(type(value) is not int or value < 0 for value in (desired, minimum, maximum)) or not minimum <= desired <= maximum:
            raise RuntimeErrorExact("sandbox customer ASG capacity is invalid")
        must_run = label == "relay" or label == f"server_{active_server}" or label == f"ac_{active_ac}"
        instances = group.get("Instances", [])
        if must_run and (desired <= 0 or len(instances) != desired):
            raise RuntimeErrorExact("active sandbox customer ASG is not full size")
        for instance in instances:
            if instance.get("HealthStatus") != "Healthy" or instance.get("LifecycleState") != "InService":
                raise RuntimeErrorExact("sandbox customer ASG instance is not ready")
        template_id, version = _launch_template(group)
        template = ec2.describe_launch_template_versions(LaunchTemplateId=template_id, Versions=[version]).get("LaunchTemplateVersions", [])
        if len(template) != 1 or type(template[0].get("VersionNumber")) is not int or template[0]["VersionNumber"] <= 0:
            raise RuntimeErrorExact("sandbox customer launch template version is ambiguous")
        resolved_version = str(template[0]["VersionNumber"])
        if version not in {"$Default", "$Latest"} and version != resolved_version:
            raise RuntimeErrorExact("sandbox customer launch template version differs from its ASG")
        encoded = template[0].get("LaunchTemplateData", {}).get("UserData")
        if not isinstance(encoded, str):
            raise RuntimeErrorExact("sandbox customer launch template has no user data")
        try:
            user_data = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise RuntimeErrorExact("sandbox customer launch template user data is invalid") from error
        if label.startswith("server_") and (
            f'AgentKeysTable = "{AGENT_TABLE}"' not in user_data
            or f'SessionControlTable = "{SESSION_TABLE}"' not in user_data
            or "NativeSessionOperations = true" not in user_data
            or RETIRED_AGENT_TABLE in user_data
        ):
            raise RuntimeErrorExact("sandbox server is not configured for the reviewed operation authority")
        repository, parameter_name = IMAGE_RUNTIME[label]
        expected_image = images.get(label)
        parameter = parameters.get(parameter_name)
        expected_repo = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{repository}"
        if (
            not isinstance(expected_image, dict)
            or set(expected_image) != {"source_sha", "image_digest"}
            or not isinstance(parameter, dict)
            or parameter.get("value") != expected_image["source_sha"]
            or type(parameter.get("last_modified_ms")) is not int
            or parameter_name not in user_data
            or expected_repo not in user_data
        ):
            raise RuntimeErrorExact("sandbox launch template image authority drifted")
        instance_ids = sorted(instance.get("InstanceId", "") for instance in instances)
        if any(re.fullmatch(r"i-[0-9a-f]+", instance_id) is None for instance_id in instance_ids):
            raise RuntimeErrorExact("sandbox customer instance identity is invalid")
        described = _instance_projection(ec2, instance_ids)
        for instance in instances:
            instance_id = instance["InstanceId"]
            asg_template = instance.get("LaunchTemplate")
            actual = described[instance_id]
            actual_template = actual.get("LaunchTemplate")
            launched = actual.get("LaunchTime")
            if (
                not isinstance(asg_template, dict)
                or asg_template.get("LaunchTemplateId") != template_id
                or asg_template.get("Version") != resolved_version
                or not isinstance(actual_template, dict)
                or actual_template.get("LaunchTemplateId") != template_id
                or actual_template.get("Version") != resolved_version
                or actual.get("State", {}).get("Name") != "running"
                or not isinstance(launched, dt.datetime)
                or launched.tzinfo is None
                or int(launched.timestamp() * 1000) < parameter["last_modified_ms"]
            ):
                raise RuntimeErrorExact("sandbox customer instance does not run the current launch/image authority")
        result[label] = {
            "name": name,
            "desired": desired,
            "min": minimum,
            "max": maximum,
            "launch_template_id": template_id,
            "launch_template_version": resolved_version,
            "image_parameter": parameter_name,
            "source_sha": expected_image["source_sha"],
            "image_digest": expected_image["image_digest"],
            "instances": instance_ids,
        }
    return result


def _table(client: Any, name: str) -> dict[str, str]:
    table = client.describe_table(TableName=name).get("Table", {})
    if table.get("TableName") != name or table.get("TableStatus") != "ACTIVE" or not isinstance(table.get("TableArn"), str):
        raise RuntimeErrorExact("sandbox operation table is not active")
    return {"name": name, "arn": table["TableArn"]}


def _cell_catalog(client: Any, source: dict[str, Any]) -> dict[str, Any]:
    response = client.get_item(
        TableName=CATALOG_TABLE,
        Key={"pk": {"S": "REGISTRY"}, "sk": {"S": "CELL#cell0"}},
        ConsistentRead=True,
    )
    item = response.get("Item")
    expected_keys = {
        "pk",
        "sk",
        "cell_id",
        "status",
        "endpoint_revision",
        "nhp_host",
        "nhp_port",
        "server_public_key_b64",
        "selection_weight",
        "updated_at",
    }
    if not isinstance(item, dict) or set(item) != expected_keys:
        raise RuntimeErrorExact("sandbox cell0 catalog row is not exact")
    expected = {
        "pk": {"S": "REGISTRY"},
        "sk": {"S": "CELL#cell0"},
        "cell_id": {"S": source["cell_id"]},
        "status": {"S": source["status"]},
        "endpoint_revision": {"N": str(source["endpoint_revision"])},
        "nhp_host": {"S": source["host"]},
        "nhp_port": {"N": str(source["port"])},
        "server_public_key_b64": {"S": source["server_public_key_b64"]},
        "selection_weight": {"N": source["selection_weight"]},
        "updated_at": {"S": source["updated_at"]},
    }
    if item != expected:
        raise RuntimeErrorExact("sandbox cell0 catalog row differs from reviewed source")
    return {
        "cell_id": source["cell_id"],
        "endpoint_revision": source["endpoint_revision"],
        "host": item["nhp_host"]["S"],
        "port": source["port"],
        "server_public_key_b64": item["server_public_key_b64"]["S"],
    }


def _qurl_index(ecr: Any, source_tag: str) -> dict[str, str]:
    response = ecr.batch_get_image(
        repositoryName="layerv/nhp-qurl",
        imageIds=[{"imageTag": source_tag}],
        acceptedMediaTypes=["application/vnd.oci.image.index.v1+json"],
    )
    if response.get("failures") or len(response.get("images", [])) != 1:
        raise RuntimeErrorExact("qurl-service source tag has no exact ECR index")
    image = response["images"][0]
    digest = image.get("imageId", {}).get("imageDigest")
    returned_tag = image.get("imageId", {}).get("imageTag")
    raw = image.get("imageManifest")
    if returned_tag != source_tag or DIGEST.fullmatch(str(digest)) is None or not isinstance(raw, str) or "sha256:" + hashlib.sha256(raw.encode()).hexdigest() != digest:
        raise RuntimeErrorExact("qurl-service ECR index digest is invalid")
    try:
        index = json.loads(raw, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, RuntimeErrorExact) as error:
        raise RuntimeErrorExact("qurl-service ECR index JSON is invalid") from error
    if not isinstance(index, dict) or set(index) != {"schemaVersion", "mediaType", "manifests"} or index["schemaVersion"] != 2 or index["mediaType"] != "application/vnd.oci.image.index.v1+json":
        raise RuntimeErrorExact("qurl-service ECR index schema drifted")
    platform = [
        row for row in index["manifests"]
        if isinstance(row, dict) and row.get("platform") == {"architecture": "amd64", "os": "linux"}
    ] if isinstance(index["manifests"], list) else []
    if len(index["manifests"]) != 2 or len(platform) != 1 or set(platform[0]) != {"mediaType", "digest", "size", "platform"} or DIGEST.fullmatch(str(platform[0].get("digest"))) is None:
        raise RuntimeErrorExact("qurl-service linux/amd64 platform is not exact")
    return {"image_digest": digest, "platform_image_digest": platform[0]["digest"]}


def _qurl_service_projection(values: dict[str, str], ecs: Any) -> dict[str, Any]:
    cluster = values["/layerv-nhp-sandbox/qurl-ecs-cluster"]
    service_name = values["/layerv-nhp-sandbox/qurl-ecs-service"]
    if cluster != QURL_SERVICE_RUNTIME or service_name != QURL_SERVICE_RUNTIME:
        raise RuntimeErrorExact("qurl-service ECS cluster/service identity drifted")
    services = ecs.describe_services(cluster=cluster, services=[service_name]).get("services", [])
    if len(services) != 1 or services[0].get("status") != "ACTIVE" or services[0].get("desiredCount") != services[0].get("runningCount") or services[0].get("desiredCount", 0) <= 0 or services[0].get("pendingCount") != 0:
        raise RuntimeErrorExact("qurl-service ECS service is not stable")
    deployments = [item for item in services[0].get("deployments", []) if item.get("status") == "PRIMARY"]
    if len(deployments) != 1 or len(services[0].get("deployments", [])) != 1 or deployments[0].get("rolloutState") != "COMPLETED" or deployments[0].get("desiredCount") != deployments[0].get("runningCount") or deployments[0].get("pendingCount") != 0:
        raise RuntimeErrorExact("qurl-service ECS deployment set is not stable")
    task_definition = deployments[0].get("taskDefinition")
    task_arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING").get("taskArns", [])
    tasks = ecs.describe_tasks(cluster=cluster, tasks=task_arns).get("tasks", [])
    if len(tasks) != services[0]["desiredCount"] or any(task.get("taskDefinitionArn") != task_definition or task.get("lastStatus") != "RUNNING" or task.get("desiredStatus") != "RUNNING" or task.get("healthStatus") != "HEALTHY" for task in tasks):
        raise RuntimeErrorExact("qurl-service tasks do not share one task definition")
    digests = set()
    for task in tasks:
        containers = [item for item in task.get("containers", []) if item.get("name") == "qurl-api"]
        if len(containers) != 1 or DIGEST.fullmatch(str(containers[0].get("imageDigest"))) is None:
            raise RuntimeErrorExact("qurl-service task image digest is invalid")
        digests.add(containers[0]["imageDigest"])
    definition = ecs.describe_task_definition(taskDefinition=task_definition).get("taskDefinition", {})
    containers = [item for item in definition.get("containerDefinitions", []) if item.get("name") == "qurl-api"]
    expected_prefix = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/layerv/nhp-qurl:"
    image = containers[0].get("image") if len(containers) == 1 else None
    source_tag = image.removeprefix(expected_prefix) if isinstance(image, str) and image.startswith(expected_prefix) else ""
    if re.fullmatch(r"[0-9a-f]{7}", source_tag) is None or len(digests) != 1:
        raise RuntimeErrorExact("qurl-service task definition source tag is not exact")
    return {"task_definition": task_definition, "task_arns": sorted(task_arns), "image_digest": digests.pop(), "source_tag": source_tag}


def _qurl_service(values: dict[str, str], ecs: Any, ecr: Any) -> dict[str, Any]:
    before = _qurl_service_projection(values, ecs)
    index = _qurl_index(ecr, before["source_tag"])
    after = _qurl_service_projection(values, ecs)
    if before != after or before["image_digest"] != index["image_digest"]:
        raise RuntimeErrorExact("qurl-service ECS/ECR runtime changed during its readiness bracket")
    return {
        "source_tag": before["source_tag"],
        "image_digest": index["image_digest"],
        "platform_image_digest": index["platform_image_digest"],
        "task_definition": before["task_definition"],
    }


def collect(session: Any) -> dict[str, Any]:
    sts, ssm = session.client("sts"), session.client("ssm")
    if sts.get_caller_identity().get("Account") != ACCOUNT or session.region_name != REGION:
        raise RuntimeErrorExact("AWS identity is not exact sandbox")
    source = _source_contract()
    before = _parameters(ssm)
    values = _parameter_values(before)
    active_server = values["/sandbox/nhp/server/active-color"]
    active_ac = values["/sandbox/nhp/ac/active-color"]
    if active_server not in {"blue", "green"} or active_ac not in {"blue", "green"}:
        raise RuntimeErrorExact("sandbox server or AC active color is invalid")
    expected_values = {
        "/sandbox/nhp/server/asg-name": ASGS["server_blue"],
        "/sandbox/nhp/server/green-asg-name": ASGS["server_green"],
        "/sandbox/nhp/ac/asg-name": ASGS["ac_blue"],
        "/sandbox/nhp/ac/green-asg-name": ASGS["ac_green"],
        "/sandbox/nhp/relay/asg-name": ASGS["relay"],
    }
    if any(values[name] != expected for name, expected in expected_values.items()):
        raise RuntimeErrorExact("sandbox cohort SSM names drifted")
    ecr = session.client("ecr")
    images = {
        "server_blue": _image(ecr, "layerv/nhp-server", values["/sandbox/nhp/server/image-tag"]),
        "server_green": _image(ecr, "layerv/nhp-server", values["/sandbox/nhp/server/green-image-tag"]),
        "ac_blue": _image(ecr, "layerv/nhp-ac", values["/sandbox/nhp/ac/image-tag"]),
        "ac_green": _image(ecr, "layerv/nhp-ac", values["/sandbox/nhp/ac/green-image-tag"]),
        "relay": _image(ecr, "layerv/nhp-relay", values["/sandbox/nhp/relay/image-tag"]),
    }
    asg_client, ec2 = session.client("autoscaling"), session.client("ec2")
    asgs = _asgs(asg_client, ec2, active_server, active_ac, images, before)
    dynamodb = session.client("dynamodb")
    catalog_before = _cell_catalog(dynamodb, source["cell"])
    tables = {
        "session_control": _table(dynamodb, SESSION_TABLE),
        "agent_keys": _table(dynamodb, AGENT_TABLE),
        "cell_catalog": _table(dynamodb, CATALOG_TABLE),
    }
    qurl_service = _qurl_service(values, session.client("ecs"), ecr)
    images_after = {
        "server_blue": _image(ecr, "layerv/nhp-server", values["/sandbox/nhp/server/image-tag"]),
        "server_green": _image(ecr, "layerv/nhp-server", values["/sandbox/nhp/server/green-image-tag"]),
        "ac_blue": _image(ecr, "layerv/nhp-ac", values["/sandbox/nhp/ac/image-tag"]),
        "ac_green": _image(ecr, "layerv/nhp-ac", values["/sandbox/nhp/ac/green-image-tag"]),
        "relay": _image(ecr, "layerv/nhp-relay", values["/sandbox/nhp/relay/image-tag"]),
    }
    asgs_after = _asgs(asg_client, ec2, active_server, active_ac, images_after, before)
    after = _parameters(ssm)
    catalog_after = _cell_catalog(dynamodb, source["cell"])
    if after != before or catalog_after != catalog_before or images_after != images or asgs_after != asgs:
        raise RuntimeErrorExact("sandbox runtime changed during its readiness bracket")
    issuer_value = values["/sandbox/nhp/qurl/qv2-issuer-key"]
    issuer_prefix = source["issuer_kid"] + "="
    if not issuer_value.startswith(issuer_prefix) or len(issuer_value) <= len(issuer_prefix):
        raise RuntimeErrorExact("sandbox issuer parameter differs from reviewed source")
    issuer_spki = issuer_value[len(issuer_prefix) :]
    try:
        if len(base64.b64decode(issuer_spki, validate=True)) < 80:
            raise RuntimeErrorExact("sandbox issuer public key is invalid")
    except ValueError as error:
        raise RuntimeErrorExact("sandbox issuer public key is invalid") from error
    try:
        fixed_contract = json.loads(
            values["/sandbox/nhp/customer-journey/fixed-canary-v1"],
            object_pairs_hook=_pairs,
        )
    except (json.JSONDecodeError, RuntimeErrorExact) as error:
        raise RuntimeErrorExact("fixed-canary runtime contract JSON is invalid") from error
    if not isinstance(fixed_contract, dict) or set(fixed_contract) != {
        "assignment_generation",
        "auth0_secret_name",
        "authority_role_arn",
        "environment",
        "otp_mailbox",
        "schema",
        "secret_map",
        "state_table",
    }:
        raise RuntimeErrorExact("fixed-canary runtime contract shape drifted")
    if fixed_contract["schema"] != 1 or fixed_contract["environment"] != "sandbox":
        raise RuntimeErrorExact("fixed-canary runtime contract identity drifted")
    assignment_generation = fixed_contract["assignment_generation"]
    if type(assignment_generation) is not int or assignment_generation <= 0:
        raise RuntimeErrorExact("fixed-canary assignment generation is invalid")
    body = {
        "schema": 1,
        "environment": "sandbox",
        "aws_account_id": ACCOUNT,
        "aws_region": REGION,
        "active_colors": {"server": active_server, "ac": active_ac},
        "cohorts": {
            "blue": {"server_asg": ASGS["server_blue"], "ac_asg": ASGS["ac_blue"], "server": images["server_blue"], "ac": images["ac_blue"]},
            "green": {"server_asg": ASGS["server_green"], "ac_asg": ASGS["ac_green"], "server": images["server_green"], "ac": images["ac_green"]},
        },
        "relay": {"asg": ASGS["relay"], "hostname": source["relay_hostname"], **images["relay"]},
        "session_control_table": SESSION_TABLE,
        "qurl_agent_keys_table": AGENT_TABLE,
        "cell_id": "cell0",
        "assignment_generation": assignment_generation,
        "hub_endpoint": {"host": "hub.nhp.layerv.xyz", "port": 443, "server_public_key_b64": values["/sandbox/nhp/control/hub/identity/public-key"]},
        "cell_endpoint": {
            "host": catalog_before["host"],
            "port": catalog_before["port"],
            "server_public_key_b64": catalog_before["server_public_key_b64"],
        },
        "frps_host": "connect.layerv.xyz",
        "issuer": {
            "kid": source["issuer_kid"],
            "spki_der_b64": issuer_spki,
        },
        "asgs": asgs,
        "tables": tables,
        "qurl_service": qurl_service,
        "parameter_versions": {name: item["version"] for name, item in before.items()},
    }
    body["runtime_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
    return body


def write_private(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise RuntimeErrorExact("runtime output path is not fresh and private")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        raw = canonical(value)
        if os.write(descriptor, raw) != len(raw):
            raise RuntimeErrorExact("runtime output write was short")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.region != REGION:
        raise RuntimeErrorExact("runtime region is not sandbox")
    import boto3

    write_private(args.output_file, collect(boto3.session.Session(region_name=args.region)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeErrorExact):
        print("sandbox fixed-canary runtime read failed", file=sys.stderr)
        raise SystemExit(1) from None

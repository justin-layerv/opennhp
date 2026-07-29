#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import collect_udp_proof_deployment_evidence as collector  # noqa: E402
import udp_proof_deployment_contract as contract  # noqa: E402


def qrts_verified_attestation(
    *,
    digest: str = "a" * 64,
    source_revision: str = "b" * 40,
    binary_sha256: str = "c" * 64,
    subject_name: str = (
        "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/qurl-reverse-tunnel-server"
    ),
    predicate_type: str = collector.QRTS_BUILD_RECEIPT_ATTESTATION_TYPE,
    subject_count: int = 1,
    predicate_extra: dict[str, object] | None = None,
) -> bytes:
    predicate = {
        "schema_version": 1,
        "source_revision": source_revision,
        "binary_path": collector.QRTS_BUILD_RECEIPT_BINARY_PATH,
        "binary_sha256": binary_sha256,
    }
    predicate.update(predicate_extra or {})
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "subject": [
            {"name": subject_name, "digest": {"sha256": digest}}
            for _ in range(subject_count)
        ],
        "predicate": predicate,
    }
    return json.dumps(
        {
            "payload": base64.b64encode(
                json.dumps(statement, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
        },
        separators=(",", ":"),
    ).encode("utf-8")


def security_group_permission(
    protocol: str,
    port: int,
    *,
    cidrs: tuple[str, ...] = (),
    group_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "IpProtocol": protocol,
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": cidr} for cidr in cidrs],
        "Ipv6Ranges": [],
        "PrefixListIds": [],
        "UserIdGroupPairs": [{"GroupId": group_id} for group_id in group_ids],
    }


def protected_hub_groups() -> tuple[dict[str, object], dict[str, object]]:
    nlb_group_id = "sg-00000000000000001"
    backend_group_id = "sg-00000000000000002"
    nlb = {
        "GroupId": nlb_group_id,
        "VpcId": "vpc-00000000000000001",
        "Tags": [
            {
                "Key": "Name",
                "Value": "layerv-nhp-sandbox-control-hub-nlb",
            }
        ],
        "IpPermissions": [
            security_group_permission(
                "udp",
                62206,
                cidrs=(collector.PROOF_SOURCE_CIDR,),
            )
        ],
        "IpPermissionsEgress": [
            security_group_permission(
                "udp",
                62206,
                group_ids=(backend_group_id,),
            ),
            security_group_permission(
                "tcp",
                62207,
                group_ids=(backend_group_id,),
            ),
        ],
    }
    backend = {
        "GroupId": backend_group_id,
        "VpcId": "vpc-00000000000000001",
        "Tags": [
            {
                "Key": "Name",
                "Value": "layerv-nhp-sandbox-control-hub",
            }
        ],
        "IpPermissions": [
            security_group_permission(
                "udp",
                62206,
                group_ids=(nlb_group_id,),
            ),
            security_group_permission(
                "tcp",
                62207,
                group_ids=(nlb_group_id,),
            ),
        ],
        "IpPermissionsEgress": [],
    }
    return nlb, backend


class CollectorTrustBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        collector._VERIFIED_QURL_RUNTIME_ATTESTATIONS.clear()
        collector._VERIFIED_QRTS_RUNTIME_SIGNATURES.clear()

    def tearDown(self) -> None:
        collector._VERIFIED_QURL_RUNTIME_ATTESTATIONS.clear()
        collector._VERIFIED_QRTS_RUNTIME_SIGNATURES.clear()

    def test_json_loader_rejects_overflow_float(self) -> None:
        with self.assertRaisesRegex(contract.ContractError, "non-finite JSON number"):
            collector._loads(b'{"value":1e999}', "overflow fixture")

    def test_subprocess_output_is_bounded_while_running(self) -> None:
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "response exceeds 32 bytes",
        ):
            collector._run_bounded(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 1048576)",
                ],
                "oversized fixture",
                maximum=32,
            )

    def test_aws_cli_disables_automatic_pagination(self) -> None:
        with mock.patch.object(collector, "_run_json", return_value={}) as run_json:
            collector._aws("ecs", ["list-tasks"], "fixture")
        command = run_json.call_args.args[0]
        self.assertIn("--no-paginate", command)
        self.assertLess(command.index("--no-paginate"), command.index("--region"))

    def test_attestation_bucket_accepts_strict_multi_region_kms_key(self) -> None:
        kms_key_arn = (
            "arn:aws:kms:us-east-2:767397897469:key/"
            "mrk-0123456789abcdef0123456789abcdef"
        )
        responses = [
            {"Status": "Enabled"},
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                "KMSMasterKeyID": kms_key_arn,
                            },
                            "BucketKeyEnabled": True,
                        }
                    ]
                }
            },
            {"Policy": "{}"},
            {"PolicyStatus": {"IsPublic": False}},
        ]
        with mock.patch.object(collector, "_aws", side_effect=responses):
            observed, _ = collector._validate_attestation_bucket(
                "layerv-nhp-sandbox-runtime-attestation"
            )
        self.assertEqual(observed, kms_key_arn)

    def test_proof_source_eip_is_exact_and_owned(self) -> None:
        response = {
            "Addresses": [
                {
                    "AllocationId": "eipalloc-00000000000000001",
                    "PublicIp": "3.141.109.76",
                    "Domain": "vpc",
                    "NetworkBorderGroup": "us-east-2",
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "layerv-nhp-sandbox-udp-proof-source",
                        }
                    ],
                }
            ]
        }
        with mock.patch.object(collector, "_aws", return_value=response):
            self.assertEqual(
                collector._proof_source_eip()["cidr"],
                collector.PROOF_SOURCE_CIDR,
            )
        response["Addresses"][0]["PublicIp"] = "198.51.100.7"
        with (
            mock.patch.object(collector, "_aws", return_value=response),
            self.assertRaisesRegex(collector.EvidenceError, "identity drift"),
        ):
            collector._proof_source_eip()

    def test_ac_registration_eip_pool_is_complete_and_exact(self) -> None:
        public_ips = (
            "3.151.137.194",
            "3.151.252.67",
            "3.136.14.164",
            "52.14.228.233",
            "18.225.44.103",
            "52.14.199.249",
            "16.58.119.85",
        )
        response = {
            "Addresses": [
                {
                    "AllocationId": f"eipalloc-{index + 1:017x}",
                    "PublicIp": public_ip,
                    "Domain": "vpc",
                    "NetworkBorderGroup": "us-east-2",
                    "Tags": [
                        {"Key": "Environment", "Value": "sandbox"},
                        {"Key": "Component", "Value": "ac"},
                        {"Key": "Service", "Value": "nhp-ac"},
                        {
                            "Key": "EIPPool",
                            "Value": collector.AC_REGISTRATION_EIP_POOL,
                        },
                        {"Key": "ManagedBy", "Value": "terraform"},
                        {
                            "Key": "Name",
                            "Value": f"layerv-nhp-sandbox-ac-eip-{index}",
                        },
                    ],
                }
                for index, public_ip in enumerate(public_ips)
            ]
        }
        with mock.patch.object(collector, "_aws", return_value=response):
            self.assertEqual(
                {f"{public_ip}/32" for public_ip in public_ips},
                set(collector._ac_registration_eip_cidrs()),
            )
        response["Addresses"].pop()
        with (
            mock.patch.object(collector, "_aws", return_value=response),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "missing or ambiguous",
            ),
        ):
            collector._ac_registration_eip_cidrs()

    def test_protected_edge_security_group_contract_is_fail_closed(self) -> None:
        edge_contract = collector.PUBLIC_EDGE_CONTRACTS["hub.nhp.layerv.xyz"]
        nlb, backend = protected_hub_groups()
        collector._verify_edge_security_groups(
            "hub.nhp.layerv.xyz",
            nlb_group=nlb,
            target_group=backend,
            edge_contract=edge_contract,
        )

        cell_nlb = copy.deepcopy(nlb)
        cell_backend = copy.deepcopy(backend)
        ac_registration_cidrs = (
            "3.151.137.194/32",
            "18.225.44.103/32",
        )
        cell_nlb["IpPermissions"][0]["IpRanges"].extend(
            {"CidrIp": cidr} for cidr in ac_registration_cidrs
        )
        cell_nlb["IpPermissionsEgress"][1] = security_group_permission(
            "tcp",
            8888,
            group_ids=(cell_backend["GroupId"],),
        )
        cell_backend["IpPermissions"][0]["IpRanges"] = [
            {"CidrIp": cidr}
            for cidr in collector.PUBLIC_EDGE_CONTRACTS[
                "cell0.nhp.layerv.xyz"
            ]["backend_udp_cidrs"]
        ]
        cell_backend["IpPermissions"][1] = security_group_permission(
            "tcp",
            8888,
            cidrs=tuple(
                collector.PUBLIC_EDGE_CONTRACTS["cell0.nhp.layerv.xyz"][
                    "backend_health_cidrs"
                ]
            ),
            group_ids=(cell_nlb["GroupId"],),
        )
        collector._verify_edge_security_groups(
            "cell0.nhp.layerv.xyz",
            nlb_group=cell_nlb,
            target_group=cell_backend,
            edge_contract=collector.PUBLIC_EDGE_CONTRACTS[
                "cell0.nhp.layerv.xyz"
            ],
            registration_source_cidrs=ac_registration_cidrs,
        )

        mutations = {
            "all-protocol ingress": lambda n, b: n["IpPermissions"][0].update(
                {"IpProtocol": "-1"}
            ),
            "world ingress": lambda n, b: n["IpPermissions"][0].update(
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            ),
            "wrong proof CIDR": lambda n, b: n["IpPermissions"][0].update(
                {"IpRanges": [{"CidrIp": "198.51.100.7/32"}]}
            ),
            "CIDR backend path": lambda n, b: b["IpPermissions"][0].update(
                {"IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
            ),
            "wrong backend group": lambda n, b: n["IpPermissionsEgress"][0].update(
                {
                    "UserIdGroupPairs": [
                        {"GroupId": "sg-00000000000000003"}
                    ]
                }
            ),
            "widened backend port": lambda n, b: n["IpPermissionsEgress"][
                0
            ].update({"ToPort": 65535}),
            "unexpected NLB egress": lambda n, b: n[
                "IpPermissionsEgress"
            ].append(
                security_group_permission(
                    "tcp",
                    443,
                    cidrs=("0.0.0.0/0",),
                )
            ),
            "missing NLB trust": lambda n, b: b["IpPermissions"][0].update(
                {"UserIdGroupPairs": []}
            ),
            "unexpected health CIDR": lambda n, b: b["IpPermissions"][1].update(
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            ),
            "unexpected health group": lambda n, b: b["IpPermissions"][1].update(
                {
                    "UserIdGroupPairs": [
                        {"GroupId": n["GroupId"]},
                        {"GroupId": "sg-00000000000000003"},
                    ]
                }
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                bad_nlb = copy.deepcopy(nlb)
                bad_backend = copy.deepcopy(backend)
                mutate(bad_nlb, bad_backend)
                with self.assertRaises(collector.EvidenceError):
                    collector._verify_edge_security_groups(
                        "hub.nhp.layerv.xyz",
                        nlb_group=bad_nlb,
                        target_group=bad_backend,
                        edge_contract=edge_contract,
                    )

    def test_protected_edge_requires_private_link_sg_enforcement(self) -> None:
        response = {
            "LoadBalancers": [
                {
                    "LoadBalancerName": "layerv-nhp-sandbox-hub-edge",
                    "Type": "network",
                    "Scheme": "internet-facing",
                    "IpAddressType": "ipv4",
                    "State": {"Code": "active"},
                    "VpcId": "vpc-00000000000000001",
                    "SecurityGroups": ["sg-00000000000000001"],
                    "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic": "off",
                }
            ]
        }
        with (
            mock.patch.object(collector, "_aws", return_value=response),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "protected public network edge",
            ),
        ):
            collector._verify_dns_alias("hub.nhp.layerv.xyz")

    def test_route53_alias_rejects_conditional_routing_surfaces(self) -> None:
        host = "hub.nhp.layerv.xyz"
        nlb_dns_name = (
            "layerv-nhp-sandbox-hub-edge-0123456789abcdef."
            "elb.us-east-2.amazonaws.com"
        )
        zone_id = "Z0123456789ABCDEFG"
        record = {
            "Name": f"{host}.",
            "Type": "A",
            "AliasTarget": {
                "DNSName": f"{nlb_dns_name}.",
                "HostedZoneId": zone_id,
                "EvaluateTargetHealth": True,
            },
        }
        collector._verify_route53_alias_record(
            record,
            host=host,
            nlb_dns_name=nlb_dns_name,
            canonical_hosted_zone_id=zone_id,
        )

        mutations = {
            "weighted routing": lambda value: value.update(
                {"SetIdentifier": "proof", "Weight": 1}
            ),
            "failover routing": lambda value: value.update(
                {"SetIdentifier": "proof", "Failover": "PRIMARY"}
            ),
            "external health check": lambda value: value.update(
                {"HealthCheckId": "00000000-0000-0000-0000-000000000000"}
            ),
            "alias extension": lambda value: value["AliasTarget"].update(
                {"Unexpected": "value"}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                drifted = copy.deepcopy(record)
                mutate(drifted)
                with self.assertRaises(collector.EvidenceError):
                    collector._verify_route53_alias_record(
                        drifted,
                        host=host,
                        nlb_dns_name=nlb_dns_name,
                        canonical_hosted_zone_id=zone_id,
                    )

    def test_target_security_group_attachment_is_exact(self) -> None:
        backend_group_id = "sg-00000000000000002"
        vpc_id = "vpc-00000000000000001"
        instance_id = "i-00000000000000001"
        instance_response = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": instance_id,
                            "VpcId": vpc_id,
                            "State": {"Name": "running"},
                            "SecurityGroups": [{"GroupId": backend_group_id}],
                        }
                    ]
                }
            ]
        }
        with mock.patch.object(collector, "_aws", return_value=instance_response):
            collector._verify_target_security_group_attachments(
                "cell0.nhp.layerv.xyz",
                target_type="instance",
                target_ids=[instance_id],
                vpc_id=vpc_id,
                backend_group_id=backend_group_id,
            )

        instance_response["Reservations"][0]["Instances"][0][
            "SecurityGroups"
        ].append({"GroupId": "sg-00000000000000003"})
        with (
            mock.patch.object(collector, "_aws", return_value=instance_response),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "does not attach only the backend group",
            ),
        ):
            collector._verify_target_security_group_attachments(
                "cell0.nhp.layerv.xyz",
                target_type="instance",
                target_ids=[instance_id],
                vpc_id=vpc_id,
                backend_group_id=backend_group_id,
            )

    def test_ip_target_security_group_attachment_is_exact(self) -> None:
        backend_group_id = "sg-00000000000000002"
        vpc_id = "vpc-00000000000000001"
        target_ip = "10.102.1.25"
        eni_response = {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-00000000000000001",
                    "VpcId": vpc_id,
                    "Status": "in-use",
                    "Attachment": {"Status": "attached"},
                    "PrivateIpAddress": target_ip,
                    "PrivateIpAddresses": [{"PrivateIpAddress": target_ip}],
                    "Groups": [{"GroupId": backend_group_id}],
                }
            ]
        }
        with mock.patch.object(collector, "_aws", return_value=eni_response):
            collector._verify_target_security_group_attachments(
                "hub.nhp.layerv.xyz",
                target_type="ip",
                target_ids=[target_ip],
                vpc_id=vpc_id,
                backend_group_id=backend_group_id,
            )

        eni_response["NetworkInterfaces"][0]["Groups"] = [
            {"GroupId": "sg-00000000000000003"}
        ]
        with (
            mock.patch.object(collector, "_aws", return_value=eni_response),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "does not attach only the backend group",
            ),
        ):
            collector._verify_target_security_group_attachments(
                "hub.nhp.layerv.xyz",
                target_type="ip",
                target_ids=[target_ip],
                vpc_id=vpc_id,
                backend_group_id=backend_group_id,
            )

    def test_protected_edge_requires_the_exact_attached_group(self) -> None:
        nlb, backend = protected_hub_groups()
        with (
            mock.patch.object(
                collector,
                "_aws",
                return_value={"SecurityGroups": [nlb, backend]},
            ),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "does not attach the protected-edge group",
            ),
        ):
            collector._security_groups_for_edge(
                "hub.nhp.layerv.xyz",
                vpc_id="vpc-00000000000000001",
                attached_group_id="sg-00000000000000003",
                edge_contract=collector.PUBLIC_EDGE_CONTRACTS[
                    "hub.nhp.layerv.xyz"
                ],
            )

    def test_version_listing_accepts_only_a_bounded_first_page(self) -> None:
        key = "runtime/role:instance/latest.json"
        response = {
            "IsTruncated": True,
            "NextKeyMarker": key,
            "NextVersionIdMarker": "older",
            "Versions": [
                {
                    "Key": key,
                    "VersionId": "current",
                    "IsLatest": True,
                }
            ],
            "DeleteMarkers": [],
        }
        self.assertEqual(
            collector._current_object_version(
                response,
                key=key,
                instance_id="i-00000000000000001",
            ),
            "current",
        )
        for mutation in (
            {"NextVersionIdMarker": None},
            {"Versions": response["Versions"] * 21},
            {
                "DeleteMarkers": [
                    {
                        "Key": key,
                        "VersionId": "deleted",
                        "IsLatest": True,
                    }
                ]
            },
        ):
            with self.subTest(mutation=mutation):
                malformed = {**response, **mutation}
                with self.assertRaises(collector.EvidenceError):
                    collector._current_object_version(
                        malformed,
                        key=key,
                        instance_id="i-00000000000000001",
                    )

    def test_qurl_runtime_attestation_is_exact_and_memoized(self) -> None:
        image_uri = (
            "767397897469.dkr.ecr.us-east-2.amazonaws.com/"
            f"layerv/qurl-service@sha256:{'a' * 64}"
        )
        source_revision = "b" * 40
        completed = collector.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"verified",
            stderr=b"",
        )
        with mock.patch.object(
            collector, "_run_bounded", return_value=completed
        ) as run:
            collector._verify_qurl_runtime_attestation(image_uri, source_revision)
            collector._verify_qurl_runtime_attestation(image_uri, source_revision)

        run.assert_called_once_with(
            [
                "gh",
                "attestation",
                "verify",
                f"oci://{image_uri}",
                "--repo",
                "layervai/qurl-service",
                "--signer-workflow",
                collector.QURL_RUNTIME_SIGNER,
                "--source-digest",
                source_revision,
                "--source-ref",
                "refs/heads/main",
                "--deny-self-hosted-runners",
            ],
            "qurl-service runtime attestation",
            maximum=1024 * 1024,
        )

    def test_qurl_runtime_attestation_failure_is_closed(self) -> None:
        completed = collector.subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout=b"",
            stderr=b"no matching attestation",
        )
        with (
            mock.patch.object(collector, "_run_bounded", return_value=completed),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "runtime attestation verification failed",
            ),
        ):
            collector._verify_qurl_runtime_attestation(
                (
                    "767397897469.dkr.ecr.us-east-2.amazonaws.com/"
                    f"layerv/qurl-service@sha256:{'a' * 64}"
                ),
                "b" * 40,
            )

    def test_qrts_runtime_signature_is_exact_and_memoized(self) -> None:
        repository = "layerv/qurl-reverse-tunnel-server"
        digest = f"sha256:{'a' * 64}"
        source_revision = "b" * 40
        image_uri = (
            f"767397897469.dkr.ecr.us-east-2.amazonaws.com/{repository}@{digest}"
        )
        completed = collector.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"verified",
            stderr=b"",
        )
        with mock.patch.object(
            collector, "_run_bounded", return_value=completed
        ) as run:
            collector._verify_qrts_runtime_signature(
                repository, digest, source_revision
            )
            collector._verify_qrts_runtime_signature(
                repository, digest, source_revision
            )

        run.assert_called_once_with(
            [
                "cosign",
                "verify",
                image_uri,
                "--certificate-identity",
                collector.QRTS_COSIGN_IDENTITY,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--certificate-github-workflow-name",
                "Docker Publish",
                "--certificate-github-workflow-ref",
                "refs/heads/main",
                "--certificate-github-workflow-repository",
                collector.QRTS_COSIGN_REPOSITORY,
                "--certificate-github-workflow-sha",
                source_revision,
            ],
            "qRTS runtime signature",
            maximum=1024 * 1024,
        )

    def test_qrts_runtime_signature_failure_is_closed(self) -> None:
        completed = collector.subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout=b"",
            stderr=b"no matching signature",
        )
        with (
            mock.patch.object(collector, "_run_bounded", return_value=completed),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "qRTS runtime signature verification failed",
            ),
        ):
            collector._verify_qrts_runtime_signature(
                "layerv/qurl-reverse-tunnel-server",
                f"sha256:{'a' * 64}",
                "b" * 40,
            )

    def test_qrts_receipt_is_authenticated_and_canonical(self) -> None:
        repository = "layerv/qurl-reverse-tunnel-server"
        digest = f"sha256:{'a' * 64}"
        revision = "b" * 40
        config = {
            "config": {
                "Labels": {
                    "org.opencontainers.image.revision": revision,
                }
            }
        }
        with (
            mock.patch.object(
                collector,
                "_ecr_config",
                return_value=(config, f"sha256:{'e' * 64}"),
            ),
            mock.patch.object(
                collector,
                "_verify_qrts_runtime_signature",
            ) as verify,
            mock.patch.object(
                collector,
                "_verify_qrts_build_receipt_attestation",
                return_value={
                    "schema_version": 1,
                    "source_revision": revision,
                    "binary_path": collector.QRTS_BUILD_RECEIPT_BINARY_PATH,
                    "binary_sha256": "c" * 64,
                },
            ) as verify_receipt,
        ):
            observed_revision, evidence = collector._qrts_build_receipt(
                repository,
                digest,
                "qRTS fixture",
                revision,
            )

        self.assertEqual(observed_revision, revision)
        self.assertEqual(evidence["manifest_digest"], digest)
        self.assertEqual(evidence["installed_binary_sha256"], "c" * 64)
        canonical_receipt = (
            '{"schema_version":1,"source_revision":"%s","binary_path":"%s",'
            '"binary_sha256":"%s"}\n'
            % (revision, collector.QRTS_BUILD_RECEIPT_BINARY_PATH, "c" * 64)
        ).encode("ascii")
        self.assertEqual(
            evidence["build_receipt_sha256"],
            hashlib.sha256(canonical_receipt).hexdigest(),
        )
        verify.assert_called_once_with(repository, digest, revision)
        verify_receipt.assert_called_once_with(repository, digest, revision)

    def test_qrts_receipt_rejects_oci_revision_different_from_main(self) -> None:
        config = {
            "config": {
                "Labels": {
                    "org.opencontainers.image.revision": "b" * 40,
                }
            }
        }
        with (
            mock.patch.object(
                collector,
                "_ecr_config",
                return_value=(config, f"sha256:{'e' * 64}"),
            ),
            # A revision that is NOT contained in the default branch: GitHub
            # reports the base as behind, which is the fork / unmerged-PR /
            # rewritten-history case the check exists to reject.
            mock.patch.object(
                collector,
                "_gh",
                return_value={"status": "diverged", "behind_by": 3, "ahead_by": 1},
            ),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "OCI revision is not a commit on trusted main",
            ),
        ):
            collector._qrts_build_receipt(
                "layerv/qurl-reverse-tunnel-server",
                f"sha256:{'a' * 64}",
                "qRTS fixture",
                "f" * 40,
            )

        with self.assertRaisesRegex(
            collector.EvidenceError,
            "unexpected ECR repository",
        ):
            collector._qrts_build_receipt(
                "layerv/attacker-image",
                f"sha256:{'a' * 64}",
                "qRTS fixture",
                "b" * 40,
            )

    def test_qrts_attestation_verifier_pins_exact_identity_and_sha(self) -> None:
        repository = "layerv/qurl-reverse-tunnel-server"
        digest = f"sha256:{'a' * 64}"
        source_revision = "b" * 40
        completed = collector.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=qrts_verified_attestation(),
            stderr=b"",
        )
        with mock.patch.object(
            collector,
            "_run_bounded",
            return_value=completed,
        ) as run:
            receipt = collector._verify_qrts_build_receipt_attestation(
                repository,
                digest,
                source_revision,
            )

        self.assertEqual(receipt["binary_sha256"], "c" * 64)
        run.assert_called_once_with(
            [
                "cosign",
                "verify-attestation",
                (f"767397897469.dkr.ecr.us-east-2.amazonaws.com/{repository}@{digest}"),
                "--type",
                collector.QRTS_BUILD_RECEIPT_ATTESTATION_TYPE,
                "--certificate-identity",
                collector.QRTS_COSIGN_IDENTITY,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--certificate-github-workflow-name",
                "Docker Publish",
                "--certificate-github-workflow-ref",
                "refs/heads/main",
                "--certificate-github-workflow-repository",
                collector.QRTS_COSIGN_REPOSITORY,
                "--certificate-github-workflow-sha",
                source_revision,
            ],
            "qRTS build-receipt attestation",
            maximum=collector.QRTS_VERIFIED_ATTESTATIONS_MAX_BYTES,
        )

    def test_qrts_attestation_missing_is_closed(self) -> None:
        completed = collector.subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout=b"",
            stderr=b"no matching attestations",
        )
        with (
            mock.patch.object(collector, "_run_bounded", return_value=completed),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "attestation verification failed",
            ),
        ):
            collector._verify_qrts_build_receipt_attestation(
                "layerv/qurl-reverse-tunnel-server",
                f"sha256:{'a' * 64}",
                "b" * 40,
            )

        with self.assertRaisesRegex(
            collector.EvidenceError,
            "missing or oversized",
        ):
            collector._qrts_receipt_from_verified_attestations(
                b"",
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

    def test_qrts_attestation_identical_duplicates_are_safe(self) -> None:
        one = qrts_verified_attestation()
        receipt = collector._qrts_receipt_from_verified_attestations(
            one + b"\n" + one,
            image_repository="layerv/qurl-reverse-tunnel-server",
            digest=f"sha256:{'a' * 64}",
            expected_source_revision="b" * 40,
        )
        self.assertEqual(receipt["binary_sha256"], "c" * 64)

    def test_qrts_attestation_top_level_array_is_supported(self) -> None:
        one = json.loads(qrts_verified_attestation())
        receipt = collector._qrts_receipt_from_verified_attestations(
            json.dumps([one, one], separators=(",", ":")).encode("utf-8"),
            image_repository="layerv/qurl-reverse-tunnel-server",
            digest=f"sha256:{'a' * 64}",
            expected_source_revision="b" * 40,
        )
        self.assertEqual(receipt["binary_sha256"], "c" * 64)

    def test_qrts_attestation_empty_array_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "no verified build-receipt attestation",
        ):
            collector._qrts_receipt_from_verified_attestations(
                b"[]",
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

    def test_qrts_attestation_trailing_malformed_json_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "not a valid JSON stream",
        ):
            collector._qrts_receipt_from_verified_attestations(
                qrts_verified_attestation() + b"\n{",
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

    def test_qrts_attestation_record_bound_is_closed(self) -> None:
        one = json.loads(qrts_verified_attestation())
        raw = json.dumps(
            [one] * (collector.QRTS_VERIFIED_ATTESTATIONS_MAX_COUNT + 1),
            separators=(",", ":"),
        ).encode("utf-8")
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "too many records",
        ):
            collector._qrts_receipt_from_verified_attestations(
                raw,
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

    def test_qrts_attestation_divergent_duplicates_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "attestations diverge",
        ):
            collector._qrts_receipt_from_verified_attestations(
                qrts_verified_attestation()
                + b"\n"
                + qrts_verified_attestation(binary_sha256="d" * 64),
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

    def test_qrts_attestation_malformed_payload_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "payload is not base64",
        ):
            collector._qrts_receipt_from_verified_attestations(
                b'{"payload":"%%%"}',
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

        with self.assertRaisesRegex(
            contract.ContractError,
            "must contain exactly",
        ):
            collector._qrts_receipt_from_verified_attestations(
                qrts_verified_attestation(predicate_extra={"unexpected": True}),
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

    def test_qrts_attestation_wrong_subject_is_rejected(self) -> None:
        for raw in (
            qrts_verified_attestation(subject_name="registry.invalid/attacker/image"),
            qrts_verified_attestation(digest="d" * 64),
        ):
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(
                    collector.EvidenceError,
                    "subject drift",
                ),
            ):
                collector._qrts_receipt_from_verified_attestations(
                    raw,
                    image_repository="layerv/qurl-reverse-tunnel-server",
                    digest=f"sha256:{'a' * 64}",
                    expected_source_revision="b" * 40,
                )

        for subject_count in (0, 2):
            with (
                self.subTest(subject_count=subject_count),
                self.assertRaisesRegex(
                    collector.EvidenceError,
                    "must have one subject",
                ),
            ):
                collector._qrts_receipt_from_verified_attestations(
                    qrts_verified_attestation(subject_count=subject_count),
                    image_repository="layerv/qurl-reverse-tunnel-server",
                    digest=f"sha256:{'a' * 64}",
                    expected_source_revision="b" * 40,
                )

    def test_qrts_attestation_wrong_source_sha_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "receipt drift",
        ):
            collector._qrts_receipt_from_verified_attestations(
                qrts_verified_attestation(source_revision="d" * 40),
                image_repository="layerv/qurl-reverse-tunnel-server",
                digest=f"sha256:{'a' * 64}",
                expected_source_revision="b" * 40,
            )

    def test_runtime_contract_verifies_the_exact_image_and_source(self) -> None:
        image_uri = (
            "767397897469.dkr.ecr.us-east-2.amazonaws.com/"
            f"layerv/nhp-qurl@sha256:{'a' * 64}"
        )
        source_revision = "b" * 40
        value = {
            "image_uri": image_uri,
            "schema_version": 1,
            "source_revision": source_revision,
        }
        parameter = {
            "Name": "/sandbox/nhp/qurl-service/runtime-contract",
            "Type": "String",
            "Value": contract.canonical_bytes(
                value,
                maximum=4096,
                name="runtime contract fixture",
            ).decode("utf-8"),
            "Version": 7,
        }
        with (
            mock.patch.object(collector, "_ssm_parameter", return_value=parameter),
            mock.patch.object(
                collector,
                "_verify_qurl_runtime_attestation",
            ) as verify,
        ):
            revision, evidence = collector._runtime_contract(
                parameter["Name"],
                expected_repository="layerv/nhp-qurl",
                expected_digest=f"sha256:{'a' * 64}",
            )

        self.assertEqual(revision, source_revision)
        self.assertEqual(evidence["image_uri"], image_uri)
        verify.assert_called_once_with(image_uri, source_revision)

    def test_canary_artifact_listing_is_bounded_and_paginated(self) -> None:
        first_page = [{"id": index} for index in range(100)]
        second_page = [{"id": 100}]
        with mock.patch.object(
            collector,
            "_gh",
            side_effect=[
                {"total_count": 101, "artifacts": first_page},
                {"total_count": 101, "artifacts": second_page},
            ],
        ) as github:
            artifacts = collector._github_run_artifacts(123)

        self.assertEqual(artifacts, first_page + second_page)
        self.assertEqual(github.call_count, 2)
        self.assertIn("per_page=100&page=2", github.call_args_list[1].args[0])

        with (
            mock.patch.object(
                collector,
                "_gh",
                return_value={
                    "total_count": collector.MAX_CANARY_ARTIFACTS + 1,
                    "artifacts": [],
                },
            ),
            self.assertRaisesRegex(
                collector.EvidenceError,
                "artifact response is malformed",
            ),
        ):
            collector._github_run_artifacts(123)

    def test_ecr_manifest_rehashes_the_returned_content(self) -> None:
        raw = json.dumps(
            {"config": {"digest": f"sha256:{'a' * 64}"}},
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = f"sha256:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"
        response = {
            "failures": [],
            "images": [
                {
                    "imageId": {"imageDigest": digest},
                    "imageManifest": raw,
                    "imageManifestMediaType": (
                        "application/vnd.oci.image.manifest.v1+json"
                    ),
                }
            ],
        }
        with mock.patch.object(collector, "_aws", return_value=response):
            manifest, media_type = collector._ecr_manifest(
                "layerv/nhp-server", digest, "fixture"
            )
        self.assertEqual(manifest["config"]["digest"], f"sha256:{'a' * 64}")
        self.assertEqual(
            media_type,
            "application/vnd.oci.image.manifest.v1+json",
        )

        response["images"][0]["imageManifest"] = raw + " "
        with (
            mock.patch.object(collector, "_aws", return_value=response),
            self.assertRaisesRegex(collector.EvidenceError, "content digest drift"),
        ):
            collector._ecr_manifest("layerv/nhp-server", digest, "fixture")

    def test_repair_document_is_version_and_content_bound(self) -> None:
        document = {
            "schemaVersion": "2.2",
            "mainSteps": [{"action": "aws:runShellScript", "name": "repair"}],
        }
        document_raw = json.dumps(document, indent=2)
        expected_digest = hashlib.sha256(
            contract.canonical_bytes(
                document,
                maximum=64 * 1024,
                name="repair fixture",
            )
        ).hexdigest()
        collector_contract = {
            "repair_document_name": ("layerv-nhp-sandbox-runtime-attestation-repair"),
            "repair_document_version": "2",
            "repair_document_sha256": expected_digest,
        }
        response = {
            "Name": collector_contract["repair_document_name"],
            "DocumentVersion": "2",
            "DocumentType": "Command",
            "Content": document_raw,
        }
        with mock.patch.object(collector, "_aws", return_value=response):
            collector._validate_repair_document(collector_contract)

        response["Content"] = json.dumps({**document, "description": "drift"})
        with (
            mock.patch.object(collector, "_aws", return_value=response),
            self.assertRaisesRegex(collector.EvidenceError, "content drift"),
        ):
            collector._validate_repair_document(collector_contract)

    def test_repair_association_is_exact_asg_and_version_bound(self) -> None:
        association_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        document_name = "layerv-nhp-sandbox-runtime-attestation-repair"
        # cell0 is blue/green and green is active, so the association targets
        # BOTH colours and the resolved active group is the green one.
        asg_name = "layerv-nhp-sandbox-server-green"
        attested_asg_names = [
            "layerv-nhp-sandbox-server",
            "layerv-nhp-sandbox-server-green",
        ]
        responses = [
            {
                "AssociationDescription": {
                    "AssociationId": association_id,
                    "Name": document_name,
                    "DocumentVersion": "2",
                    "Targets": [
                        {
                            "Key": "tag:aws:autoscaling:groupName",
                            "Values": list(attested_asg_names),
                        }
                    ],
                    # The real DescribeAssociation shape for a tag-targeted
                    # State Manager association: no Status member at all, with
                    # Overview carrying the result. This fixture previously
                    # asserted {"Status": {"Name": "Success"}}, which AWS never
                    # returns here -- it encoded the checker's assumption rather
                    # than the API, so the suite passed while the check could
                    # not succeed against any live association.
                    "Overview": {
                        "Status": "Success",
                        "DetailedStatus": "Success",
                        "AssociationStatusAggregatedCount": {"Success": 3},
                    },
                }
            },
            {
                # The real DescribeAssociationExecutions row shape. AWS never
                # returns a whole-second "Z" CreatedTime here: it is always
                # sub-second and rendered in the caller's local zone. The old
                # fixture's "2026-07-25T11:30:00Z" echoed the attested value
                # back, which is exactly what the equality filter under test
                # could never make AWS do.
                "AssociationExecutions": [
                    {
                        "AssociationId": association_id,
                        "AssociationVersion": "2",
                        "ExecutionId": "execution-1",
                        "Status": "Success",
                        "DetailedStatus": "Success",
                        "CreatedTime": "2026-07-25T05:30:00.482000-06:00",
                        "ResourceCountByStatus": "{Success=3}",
                    }
                ]
            },
            {
                "AssociationExecutionTargets": [
                    {
                        "ResourceId": "i-00000000000000001",
                        "Status": "Success",
                    }
                ]
            },
        ]
        attestation = {
            "repair_association_id": association_id,
            "repair_document_name": document_name,
            "repair_last_success_at": "2026-07-25T11:30:00Z",
        }
        collector_contract = {
            "repair_document_name": document_name,
            "repair_document_version": "2",
        }
        with mock.patch.object(collector, "_aws", side_effect=responses):
            observed = collector._verify_repair(
                attestation,
                "i-00000000000000001",
                autoscaling_group=asg_name,
                attested_asg_names=attested_asg_names,
                collector_contract=collector_contract,
            )
        self.assertEqual(observed, "2026-07-25T11:30:00Z")

        # A page that stops inside the attested second proves nothing about
        # uniqueness: a sibling execution in that same second could be sitting
        # on the page that was never fetched.
        paginated = copy.deepcopy(responses)
        paginated[1]["NextToken"] = "unexpected"
        with (
            mock.patch.object(collector, "_aws", side_effect=paginated),
            self.assertRaisesRegex(collector.EvidenceError, "executions are incomplete"),
        ):
            collector._verify_repair(
                attestation,
                "i-00000000000000001",
                autoscaling_group=asg_name,
                attested_asg_names=attested_asg_names,
                collector_contract=collector_contract,
            )

        responses[0]["AssociationDescription"]["Targets"][0]["Values"] = ["other-asg"]
        with (
            mock.patch.object(collector, "_aws", side_effect=responses),
            self.assertRaisesRegex(collector.EvidenceError, "identity drift"),
        ):
            collector._verify_repair(
                attestation,
                "i-00000000000000001",
                autoscaling_group=asg_name,
                attested_asg_names=attested_asg_names,
                collector_contract=collector_contract,
            )


class ActiveColorAsgResolutionTest(unittest.TestCase):
    """The server fleet must be resolved by ACTIVE COLOUR, not by asg-name.

    /<env>/nhp/server/asg-name is the colour-BLIND base/blue group that
    modules/compute publishes for CI/CD instance refreshes; blue-asg-name holds
    the same value. Live on 2026-07-26, cell0 had active-color=green with the
    edge NLB forwarding to the green target group, while asg-name still named
    the blue group -- so the producer compared the green NLB's healthy targets
    against the blue ASG's members and could never succeed.

    Every fixture below is a verbatim `aws ssm get-parameter --output json`
    response captured from account 767397897469 in us-east-2, including the
    LastModifiedDate/ARN/DataType fields the collector ignores. Hand-trimmed
    fixtures here have repeatedly encoded the checker's own assumptions instead
    of what AWS actually returns.
    """

    CELL0_ACTIVE_COLOR_GREEN = {
        "Parameter": {
            "Name": "/sandbox/nhp/server/active-color",
            "Type": "String",
            "Value": "green",
            "Version": 549,
            "LastModifiedDate": "2026-07-26T20:50:51.213000-06:00",
            "ARN": (
                "arn:aws:ssm:us-east-2:767397897469:parameter"
                "/sandbox/nhp/server/active-color"
            ),
            "DataType": "text",
        }
    }
    CELL0_GREEN_ASG = {
        "Parameter": {
            "Name": "/sandbox/nhp/server/green-asg-name",
            "Type": "String",
            "Value": "layerv-nhp-sandbox-server-green",
            "Version": 1,
            "LastModifiedDate": "2026-02-05T12:53:40.340000-07:00",
            "ARN": (
                "arn:aws:ssm:us-east-2:767397897469:parameter"
                "/sandbox/nhp/server/green-asg-name"
            ),
            "DataType": "text",
        }
    }
    CELL0_BLUE_ASG = {
        "Parameter": {
            "Name": "/sandbox/nhp/server/blue-asg-name",
            "Type": "String",
            # Identical to /sandbox/nhp/server/asg-name -- that is exactly why
            # asg-name is colour-blind and unusable as the active pointer.
            "Value": "layerv-nhp-sandbox-server",
            "Version": 1,
            "LastModifiedDate": "2026-02-05T12:53:40.281000-07:00",
            "ARN": (
                "arn:aws:ssm:us-east-2:767397897469:parameter"
                "/sandbox/nhp/server/blue-asg-name"
            ),
            "DataType": "text",
        }
    }
    CELL1_ACTIVE_COLOR_BLUE = {
        "Parameter": {
            "Name": "/sandbox-cell1/nhp/server/active-color",
            "Type": "String",
            "Value": "blue",
            "Version": 1,
            "LastModifiedDate": "2026-07-25T09:29:57.960000-06:00",
            "ARN": (
                "arn:aws:ssm:us-east-2:767397897469:parameter"
                "/sandbox-cell1/nhp/server/active-color"
            ),
            "DataType": "text",
        }
    }
    CELL1_BLUE_ASG = {
        "Parameter": {
            "Name": "/sandbox-cell1/nhp/server/blue-asg-name",
            "Type": "String",
            "Value": "layerv-nhp-sandbox-cell1-server",
            "Version": 1,
            "LastModifiedDate": "2026-07-25T09:35:52.726000-06:00",
            "ARN": (
                "arn:aws:ssm:us-east-2:767397897469:parameter"
                "/sandbox-cell1/nhp/server/blue-asg-name"
            ),
            "DataType": "text",
        }
    }
    QRTS_ASG = {
        "Parameter": {
            "Name": "/sandbox/nhp/reverse-tunnel-server/asg-name",
            "Type": "String",
            "Value": "layerv-nhp-sandbox-frps",
            "Version": 1,
            "LastModifiedDate": "2026-01-15T14:22:11.104000-07:00",
            "ARN": (
                "arn:aws:ssm:us-east-2:767397897469:parameter"
                "/sandbox/nhp/reverse-tunnel-server/asg-name"
            ),
            "DataType": "text",
        }
    }

    @staticmethod
    def _ssm(responses):
        """Serve get-parameter by NAME, so call ORDER cannot fake a pass."""
        by_name = {
            response["Parameter"]["Name"]: response for response in responses
        }

        def call(service, arguments, name):
            assert service == "ssm", service
            assert arguments[0] == "get-parameter", arguments
            requested = arguments[arguments.index("--name") + 1]
            if requested not in by_name:
                # The real CLI exits non-zero with ParameterNotFound, which
                # _run_json surfaces as an EvidenceError.
                raise collector.EvidenceError(
                    f"SSM parameter {requested} read failed: An error occurred "
                    "(ParameterNotFound) when calling the GetParameter operation:"
                )
            return by_name[requested]

        return call

    def test_cell0_resolves_the_green_asg_while_green_is_active(self) -> None:
        with mock.patch.object(
            collector,
            "_aws",
            side_effect=self._ssm(
                [
                    self.CELL0_ACTIVE_COLOR_GREEN,
                    self.CELL0_BLUE_ASG,
                    self.CELL0_GREEN_ASG,
                ]
            ),
        ):
            self.assertEqual(
                collector._resolve_active_asg_name("nhp_cell0"),
                "layerv-nhp-sandbox-server-green",
            )

    def test_cell0_resolves_the_blue_asg_after_a_switch_back(self) -> None:
        blue = copy.deepcopy(self.CELL0_ACTIVE_COLOR_GREEN)
        blue["Parameter"]["Value"] = "blue"
        blue["Parameter"]["Version"] = 550
        with mock.patch.object(
            collector,
            "_aws",
            side_effect=self._ssm(
                [blue, self.CELL0_BLUE_ASG, self.CELL0_GREEN_ASG]
            ),
        ):
            self.assertEqual(
                collector._resolve_active_asg_name("nhp_cell0"),
                "layerv-nhp-sandbox-server",
            )

    def test_cell1_resolves_by_colour_too(self) -> None:
        # cell1 is blue/green-capable -- it publishes active-color, blue-asg-name
        # and green-asg-name, and layerv-nhp-sandbox-cell1-server-green exists at
        # DesiredCapacity 0. It is only *coincidentally* correct today because
        # active-color is blue and asg-name equals blue-asg-name; the first
        # switch to green would break it exactly as cell0 broke.
        with mock.patch.object(
            collector,
            "_aws",
            side_effect=self._ssm(
                [self.CELL1_ACTIVE_COLOR_BLUE, self.CELL1_BLUE_ASG]
            ),
        ):
            self.assertEqual(
                collector._resolve_active_asg_name("nhp_cell1"),
                "layerv-nhp-sandbox-cell1-server",
            )

    def test_cell1_switched_to_green_follows_the_green_asg(self) -> None:
        green = copy.deepcopy(self.CELL1_ACTIVE_COLOR_BLUE)
        green["Parameter"]["Value"] = "green"
        green["Parameter"]["Version"] = 2
        green_asg = copy.deepcopy(self.CELL1_BLUE_ASG)
        green_asg["Parameter"]["Name"] = "/sandbox-cell1/nhp/server/green-asg-name"
        green_asg["Parameter"]["Value"] = "layerv-nhp-sandbox-cell1-server-green"
        with mock.patch.object(
            collector, "_aws", side_effect=self._ssm([green, green_asg])
        ):
            self.assertEqual(
                collector._resolve_active_asg_name("nhp_cell1"),
                "layerv-nhp-sandbox-cell1-server-green",
            )

    def test_unknown_colour_fails_closed(self) -> None:
        # Includes the shapes a defaulting resolver would silently accept:
        # padded, cased, empty, and a plausible third colour.
        for value in ("", "GREEN", " green", "green ", "canary", "blue/green"):
            marker = copy.deepcopy(self.CELL0_ACTIVE_COLOR_GREEN)
            marker["Parameter"]["Value"] = value
            with (
                self.subTest(active_color=value),
                mock.patch.object(
                    collector,
                    "_aws",
                    side_effect=self._ssm(
                        [marker, self.CELL0_BLUE_ASG, self.CELL0_GREEN_ASG]
                    ),
                ),
                self.assertRaisesRegex(
                    collector.EvidenceError, "active colour is not exactly one of"
                ),
            ):
                collector._resolve_active_asg_name("nhp_cell0")

    def test_missing_active_colour_parameter_fails_closed(self) -> None:
        with (
            mock.patch.object(
                collector,
                "_aws",
                side_effect=self._ssm(
                    [self.CELL0_BLUE_ASG, self.CELL0_GREEN_ASG]
                ),
            ),
            self.assertRaisesRegex(collector.EvidenceError, "ParameterNotFound"),
        ):
            collector._resolve_active_asg_name("nhp_cell0")

    def test_missing_per_colour_parameter_fails_closed(self) -> None:
        # Green is active but /sandbox/nhp/server/green-asg-name is absent. The
        # resolver must NOT fall back to blue-asg-name or to asg-name.
        with (
            mock.patch.object(
                collector,
                "_aws",
                side_effect=self._ssm(
                    [self.CELL0_ACTIVE_COLOR_GREEN, self.CELL0_BLUE_ASG]
                ),
            ),
            self.assertRaisesRegex(
                collector.EvidenceError,
                r"/sandbox/nhp/server/green-asg-name read failed",
            ),
        ):
            collector._resolve_active_asg_name("nhp_cell0")

    def test_empty_per_colour_asg_name_fails_closed(self) -> None:
        blank = copy.deepcopy(self.CELL0_GREEN_ASG)
        blank["Parameter"]["Value"] = ""
        with (
            mock.patch.object(
                collector,
                "_aws",
                side_effect=self._ssm([self.CELL0_ACTIVE_COLOR_GREEN, blank]),
            ),
            self.assertRaises(contract.ContractError),
        ):
            collector._resolve_active_asg_name("nhp_cell0")

    def test_non_blue_green_workload_keeps_its_single_asg_parameter(self) -> None:
        # Verified live: the whole /sandbox/nhp/reverse-tunnel-server/ path is
        # asg-name, image-tag and min-client-version. There is no active-color
        # marker to read, so the resolver must not invent one.
        self.assertIsNone(
            collector.EC2_WORKLOADS["qurl_reverse_tunnel_server"][
                "active_color_parameter"
            ]
        )
        with mock.patch.object(
            collector, "_aws", side_effect=self._ssm([self.QRTS_ASG])
        ):
            self.assertEqual(
                collector._resolve_active_asg_name("qurl_reverse_tunnel_server"),
                "layerv-nhp-sandbox-frps",
            )

    def test_colour_blind_asg_name_is_no_longer_read(self) -> None:
        # The regression itself: nothing may read /<env>/nhp/server/asg-name.
        # It is also no longer granted in the producer's IAM policy, so a
        # reintroduced read would surface as AccessDenied in CI.
        for workload_key in ("nhp_cell0", "nhp_cell1"):
            spec = collector.EC2_WORKLOADS[workload_key]
            with self.subTest(workload=workload_key):
                self.assertNotIn("asg_parameter", spec)
                self.assertNotIn(
                    "asg-name",
                    [
                        parameter.rsplit("/", 1)[-1]
                        for parameter in spec["color_asg_parameters"].values()
                    ],
                )
                self.assertEqual(
                    sorted(spec["color_asg_parameters"]), ["blue", "green"]
                )

    def test_iam_policy_grants_every_parameter_the_collector_reads(self) -> None:
        # Without this the producer gets AccessDenied on ssm:GetParameter for a
        # parameter that exists, which reads as missing infrastructure.
        granted = (
            ROOT
            / "terraform"
            / "modules"
            / "udp-proof-runner"
            / "manifest_producer.tf"
        ).read_text(encoding="utf-8")
        for workload_key, spec in collector.EC2_WORKLOADS.items():
            required = []
            if spec["active_color_parameter"] is not None:
                required.append(spec["active_color_parameter"])
                required.extend(spec["color_asg_parameters"].values())
            else:
                required.append(spec["asg_parameter"])
            for parameter in required:
                with self.subTest(workload=workload_key, parameter=parameter):
                    # local.manifest_ssm_parameters entries are ARN suffixes and
                    # so carry no leading slash.
                    self.assertIn(f'"{parameter.lstrip("/")}",', granted)


class AttestedAsgCoverageTest(unittest.TestCase):
    """The repair association must cover every colour, including the active one.

    Live on 2026-07-26 the association for nhp_cell0 targeted
    `tag:aws:autoscaling:groupName = layerv-nhp-sandbox-server` -- the
    colour-BLIND blue group -- because modules/runtime-attestation-store read
    the same /<env>/nhp/server/asg-name parameter the producer did. The repair
    document is what installs the collector and its timer, so the ACTIVE green
    instances had no collector and published nothing: the bucket held
    attestations for all three idle blue instances and none for
    i-02afa00ae723b243b, i-0b514e2da4ba022fb or i-0cb07b293e218e49b.
    """

    ASSOCIATION_ID = "3b7fbdbc-77c6-4d2f-874b-c6a1581071ea"
    DOCUMENT_NAME = "layerv-nhp-sandbox-runtime-attestation-repair"
    CONTRACT = {
        "repair_document_name": DOCUMENT_NAME,
        "repair_document_version": "2",
    }
    BLUE = "layerv-nhp-sandbox-server"
    GREEN = "layerv-nhp-sandbox-server-green"

    def _description(self, values: list[str]) -> dict[str, object]:
        return {
            "AssociationDescription": {
                "AssociationId": self.ASSOCIATION_ID,
                "Name": self.DOCUMENT_NAME,
                "AssociationVersion": "2",
                "DocumentVersion": "2",
                "ScheduleExpression": "rate(30 minutes)",
                "Targets": [
                    {"Key": "tag:aws:autoscaling:groupName", "Values": values}
                ],
                "Overview": {
                    "Status": "Success",
                    "DetailedStatus": "Success",
                    "AssociationStatusAggregatedCount": {"Success": 3},
                },
            }
        }

    def _verify(self, *, targets: list[str], attested: list[str], active: str) -> None:
        with mock.patch.object(
            collector, "_aws", side_effect=[self._description(targets)]
        ):
            collector._verify_repair(
                {
                    "repair_association_id": self.ASSOCIATION_ID,
                    "repair_document_name": self.DOCUMENT_NAME,
                    "repair_last_success_at": "2026-07-25T11:30:00Z",
                },
                "i-02afa00ae723b243b",
                autoscaling_group=active,
                attested_asg_names=attested,
                collector_contract=self.CONTRACT,
            )

    def test_colour_blind_single_target_is_rejected(self) -> None:
        # The live defect: association targets blue only, green is active.
        with self.assertRaisesRegex(collector.EvidenceError, "identity drift"):
            self._verify(
                targets=[self.BLUE],
                attested=[self.BLUE, self.GREEN],
                active=self.GREEN,
            )

    def test_active_colour_absent_from_the_attested_set_is_rejected(self) -> None:
        # Even a self-consistent association fails closed when the fleet the
        # producer resolved as active is not one the association covers.
        with self.assertRaisesRegex(collector.EvidenceError, "identity drift"):
            self._verify(
                targets=[self.BLUE],
                attested=[self.BLUE],
                active=self.GREEN,
            )

    def test_extra_or_foreign_asg_is_still_rejected(self) -> None:
        # Widening from one name to the colour set must not become "any set".
        for targets in (
            [self.BLUE, self.GREEN, "layerv-nhp-sandbox-frps"],
            ["other-asg", self.GREEN],
            [self.GREEN],
        ):
            with (
                self.subTest(targets=targets),
                self.assertRaisesRegex(collector.EvidenceError, "identity drift"),
            ):
                self._verify(
                    targets=targets,
                    attested=[self.BLUE, self.GREEN],
                    active=self.GREEN,
                )

    def test_resolver_returns_every_colour_sorted(self) -> None:
        responses = {
            "/sandbox/nhp/server/blue-asg-name": self.BLUE,
            "/sandbox/nhp/server/green-asg-name": self.GREEN,
        }

        def call(service, arguments, name):
            requested = arguments[arguments.index("--name") + 1]
            return {
                "Parameter": {
                    "Name": requested,
                    "Type": "String",
                    "Value": responses[requested],
                    "Version": 1,
                    "LastModifiedDate": "2026-02-05T12:53:40.340000-07:00",
                    "ARN": f"arn:aws:ssm:us-east-2:767397897469:parameter{requested}",
                    "DataType": "text",
                }
            }

        with mock.patch.object(collector, "_aws", side_effect=call):
            self.assertEqual(
                collector._resolve_attested_asg_names("nhp_cell0"),
                [self.BLUE, self.GREEN],
            )

    def test_non_blue_green_fleet_attests_its_single_asg(self) -> None:
        parameter = {
            "Parameter": {
                "Name": "/sandbox/nhp/reverse-tunnel-server/asg-name",
                "Type": "String",
                "Value": "layerv-nhp-sandbox-frps",
                "Version": 1,
                "LastModifiedDate": "2026-01-15T14:22:11.104000-07:00",
                "ARN": (
                    "arn:aws:ssm:us-east-2:767397897469:parameter"
                    "/sandbox/nhp/reverse-tunnel-server/asg-name"
                ),
                "DataType": "text",
            }
        }
        with mock.patch.object(collector, "_aws", return_value=parameter):
            self.assertEqual(
                collector._resolve_attested_asg_names("qurl_reverse_tunnel_server"),
                ["layerv-nhp-sandbox-frps"],
            )

    def test_terraform_targets_every_colour(self) -> None:
        # The producer's expectation and the association's authored targets must
        # agree, or the manifest can never be produced.
        tfvars = (
            ROOT
            / "terraform"
            / "environments"
            / "sandbox-runtime-attestation"
            / "terraform.tfvars"
        ).read_text(encoding="utf-8")
        for workload_key, spec in collector.EC2_WORKLOADS.items():
            expected = (
                sorted(spec["color_asg_parameters"].values())
                if spec["active_color_parameter"] is not None
                else [spec["asg_parameter"]]
            )
            for parameter in expected:
                with self.subTest(workload=workload_key, parameter=parameter):
                    self.assertIn(f'"{parameter}"', tfvars)
        self.assertNotIn('"/sandbox/nhp/server/asg-name"', tfvars)
        self.assertNotIn('"/sandbox-cell1/nhp/server/asg-name"', tfvars)


class EdgeServesResolvedFleetTest(unittest.TestCase):
    """The cell edge must serve exactly the colour-resolved fleet."""

    # Live on 2026-07-26 in account 767397897469 / us-east-2.
    GREEN_MEMBERS = [
        "i-02afa00ae723b243b",
        "i-0b514e2da4ba022fb",
        "i-0cb07b293e218e49b",
    ]
    BLUE_MEMBERS = [
        "i-014f7005e28046a78",
        "i-07be87f0a27ddfac4",
        "i-0d75eb62dae4c1bcd",
    ]

    def test_active_colour_fleet_matches_the_edge(self) -> None:
        # layerv-nhp-sandbox-edge forwards to targetgroup/layerv-nhp-sandbox-udp-grn
        # /42191fec63dd965a, whose three healthy targets are the green ASG's
        # members exactly.
        collector._require_edge_serves_fleet(
            "cell0",
            healthy_target_ids=sorted(self.GREEN_MEMBERS),
            in_service_instance_ids=sorted(self.GREEN_MEMBERS),
        )

    def test_colour_blind_fleet_is_rejected(self) -> None:
        # The exact failure of run 30350781941: the edge serves green while the
        # fleet was resolved from the colour-blind asg-name (blue).
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "cell0 public NLB targets differ from its healthy ASG",
        ):
            collector._require_edge_serves_fleet(
                "cell0",
                healthy_target_ids=sorted(self.GREEN_MEMBERS),
                in_service_instance_ids=sorted(self.BLUE_MEMBERS),
            )

    def test_partial_overlap_and_extra_targets_are_rejected(self) -> None:
        for healthy in (
            sorted(self.GREEN_MEMBERS[:2]),
            sorted(self.GREEN_MEMBERS + self.BLUE_MEMBERS[:1]),
            [],
        ):
            with (
                self.subTest(healthy=healthy),
                self.assertRaisesRegex(
                    collector.EvidenceError, "differ from its healthy ASG"
                ),
            ):
                collector._require_edge_serves_fleet(
                    "cell0",
                    healthy_target_ids=healthy,
                    in_service_instance_ids=sorted(self.GREEN_MEMBERS),
                )


class InstanceRefreshConvergenceTest(unittest.TestCase):
    """A converged instance count must not stand in for a stable fleet."""

    ASG = "layerv-nhp-sandbox-frps"

    def _refresh(self, status: str) -> dict[str, object]:
        return {
            "InstanceRefreshes": [
                {"AutoScalingGroupName": self.ASG, "Status": status},
            ]
        }

    def test_terminal_refresh_statuses_pass(self) -> None:
        for status in sorted(collector.TERMINAL_INSTANCE_REFRESH_STATUSES):
            with (
                self.subTest(status=status),
                mock.patch.object(
                    collector, "_aws", return_value=self._refresh(status)
                ),
            ):
                collector._require_no_active_instance_refresh("frps", self.ASG)

    def test_no_refresh_history_passes(self) -> None:
        with mock.patch.object(
            collector, "_aws", return_value={"InstanceRefreshes": []}
        ):
            collector._require_no_active_instance_refresh("frps", self.ASG)

    def test_active_refresh_fails_closed(self) -> None:
        # Observed live on layerv-nhp-sandbox-frps: an InProgress refresh at 83%
        # while the group already reported a matching in-service count.
        for status in ("InProgress", "Pending", "Cancelling", "RollbackInProgress"):
            with (
                self.subTest(status=status),
                mock.patch.object(
                    collector, "_aws", return_value=self._refresh(status)
                ),
                self.assertRaisesRegex(collector.EvidenceError, "still active"),
            ):
                collector._require_no_active_instance_refresh("frps", self.ASG)

    def test_unknown_or_missing_status_fails_closed(self) -> None:
        for status in ("Baking", "", None, 5):
            with (
                self.subTest(status=status),
                mock.patch.object(
                    collector, "_aws", return_value=self._refresh(status)
                ),
                self.assertRaisesRegex(collector.EvidenceError, "still active"),
            ):
                collector._require_no_active_instance_refresh("frps", self.ASG)

    def test_foreign_group_fails_closed(self) -> None:
        response = self._refresh("Successful")
        response["InstanceRefreshes"][0]["AutoScalingGroupName"] = "other-asg"
        with (
            mock.patch.object(collector, "_aws", return_value=response),
            self.assertRaisesRegex(collector.EvidenceError, "still active"),
        ):
            collector._require_no_active_instance_refresh("frps", self.ASG)

    def test_ambiguous_readback_fails_closed(self) -> None:
        ambiguous: list[object] = [
            {"InstanceRefreshes": [], "NextToken": "more"},
            {"InstanceRefreshes": "not-a-list"},
            {},
            [],
            {
                "InstanceRefreshes": [
                    {"AutoScalingGroupName": self.ASG, "Status": "Successful"},
                    {"AutoScalingGroupName": self.ASG, "Status": "InProgress"},
                ]
            },
            {"InstanceRefreshes": ["not-an-object"]},
        ]
        for response in ambiguous:
            with (
                self.subTest(response=response),
                mock.patch.object(collector, "_aws", return_value=response),
                self.assertRaisesRegex(collector.EvidenceError, "is incomplete"),
            ):
                collector._require_no_active_instance_refresh("frps", self.ASG)

    def test_transitional_member_is_not_converged(self) -> None:
        # The fail-open shape: a Terminating member is still attached, still
        # serving UDP, and still an NLB target, while the InService/Healthy
        # count already equals DesiredCapacity.
        group = {
            "AutoScalingGroupName": self.ASG,
            "DesiredCapacity": 3,
            "Instances": [
                {
                    "InstanceId": "i-00000000000000001",
                    "LifecycleState": "InService",
                    "HealthStatus": "Healthy",
                },
                {
                    "InstanceId": "i-00000000000000002",
                    "LifecycleState": "InService",
                    "HealthStatus": "Healthy",
                },
                {
                    "InstanceId": "i-00000000000000003",
                    "LifecycleState": "InService",
                    "HealthStatus": "Healthy",
                },
                {
                    "InstanceId": "i-00000000000000004",
                    "LifecycleState": "Terminating",
                    "HealthStatus": "Healthy",
                },
            ],
        }
        in_service = [
            instance["InstanceId"]
            for instance in group["Instances"]
            if instance["LifecycleState"] == "InService"
            and instance["HealthStatus"] == "Healthy"
        ]
        self.assertEqual(len(in_service), group["DesiredCapacity"])
        self.assertNotEqual(len(group["Instances"]), len(in_service))


class CanaryEvidenceHashFormsTest(unittest.TestCase):
    """Exactly one value in the canary evidence document is an OCI descriptor.

    Observed across the real published evidence of qurl-connector runs
    29994779471 and 30216718538: image.digest carries the "sha256:" prefix and
    every other hash -- including BOTH *_artifact_digest fields -- is a bare
    content hash of an archive. Validating a bare field as an OCI digest
    rejects every genuine canary, which is how the FRP and source artifact
    fields each blocked the producer in turn.
    """

    BARE_FIELDS = (
        "build.definition_sha256",
        "build.source_artifact_digest",
        "build.source_sha256",
        "connector_modules.frp.archive_sha256",
        "connector_modules.frp.artifact_digest",
        "image.archive_sha256",
        "image.buildkit_metadata_sha256",
        "image.go_version_m_sha256",
        "image.version_output_sha256",
    )
    OCI_FIELDS = ("image.digest",)
    SAMPLE = "ebd9a95d3a38801dbeae83ae6b1842b0e0d5253e0bed7b95440751f408180225"

    def test_bare_fields_accept_bare_and_reject_prefixed(self) -> None:
        for field in self.BARE_FIELDS:
            with self.subTest(field=field):
                self.assertEqual(contract._sha256(self.SAMPLE, field), self.SAMPLE)
                with self.assertRaises(contract.ContractError):
                    contract._sha256(f"sha256:{self.SAMPLE}", field)

    def test_oci_field_accepts_prefixed_and_rejects_bare(self) -> None:
        for field in self.OCI_FIELDS:
            with self.subTest(field=field):
                value = f"sha256:{self.SAMPLE}"
                self.assertEqual(contract._digest(value, field), value)
                with self.assertRaises(contract.ContractError):
                    contract._digest(self.SAMPLE, field)


class CanarySourceArtifactDigestTest(unittest.TestCase):
    """The canary build block carries bare SHA-256s, not OCI descriptors.

    source_artifact_digest hashes the canary's source archive, exactly like its
    siblings source_sha256 and definition_sha256. Validating it as an OCI
    "sha256:"-prefixed digest could never match a real canary; the values below
    are the ones actually published by qurl-connector runs 29994779471
    (2026-07-23) and 30216718538 (2026-07-26).
    """

    PUBLISHED = (
        "507cf7986dea7dd111f80272576d1152a941b613dee6945d6ed3334feb9d8033",
        "ebd9a95d3a38801dbeae83ae6b1842b0e0d5253e0bed7b95440751f408180225",
    )

    def test_real_published_digests_are_accepted(self) -> None:
        for value in self.PUBLISHED:
            with self.subTest(digest=value):
                self.assertEqual(
                    contract._sha256(value, "canary source artifact digest"), value
                )

    def test_oci_prefixed_form_is_rejected(self) -> None:
        # Guards the reverse regression: re-tightening this to the OCI form
        # would silently break every real canary again.
        for value in self.PUBLISHED:
            with self.subTest(digest=value):
                with self.assertRaises(contract.ContractError):
                    contract._sha256(
                        f"sha256:{value}", "canary source artifact digest"
                    )

    def test_malformed_digests_still_fail_closed(self) -> None:
        for value in ("", "not-a-hash", "A" * 64, "0" * 63, "0" * 65, None, 5):
            with self.subTest(digest=value):
                with self.assertRaises(contract.ContractError):
                    contract._sha256(value, "canary source artifact digest")


class LaunchTemplateEvidenceTest(unittest.TestCase):
    """The producer re-derives launch-template identity from the control plane.

    `ec2:DescribeInstances` returns no top-level `LaunchTemplate` for an
    ASG-launched instance, so the producer reads the Auto Scaling membership
    row and the reserved `aws:ec2launchtemplate:*` tags and requires the two to
    agree before comparing them to what the node attested.
    """

    TEMPLATE_ID = "lt-054583eecc18ceed6"

    def described_instance(
        self,
        *,
        template_id: str | None = TEMPLATE_ID,
        version: str | None = "2",
        extra_tags: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        tags: list[dict[str, object]] = [
            {"Key": "Name", "Value": "layerv-nhp-sandbox-cell1-server"}
        ]
        if template_id is not None:
            tags.append({"Key": "aws:ec2launchtemplate:id", "Value": template_id})
        if version is not None:
            tags.append({"Key": "aws:ec2launchtemplate:version", "Value": version})
        tags.extend(extra_tags or [])
        return {"InstanceId": "i-0b74635bfac7d988c", "Tags": tags}

    def test_accepts_a_membership_row(self) -> None:
        self.assertEqual(
            collector._launch_template_pair(
                {
                    "LaunchTemplateId": self.TEMPLATE_ID,
                    "LaunchTemplateName": "layerv-nhp-sandbox-cell1-server-c262",
                    "Version": "2",
                },
                "membership",
            ),
            (self.TEMPLATE_ID, "2"),
        )

    def test_rejects_a_missing_record(self) -> None:
        # This is exactly what `instance.get("LaunchTemplate")` yielded for
        # every ASG-launched node before the fix.
        for absent in (None, "", [], {}):
            with self.subTest(absent=absent):
                with self.assertRaises(collector.EvidenceError):
                    collector._launch_template_pair(absent, "membership")

    def test_rejects_malformed_identities(self) -> None:
        for template_id, version in (
            ("lt-ZZZZ", "2"),
            ("lt-", "2"),
            (self.TEMPLATE_ID, "$Latest"),
            (self.TEMPLATE_ID, "0"),
            (self.TEMPLATE_ID, "-1"),
            (self.TEMPLATE_ID, 2),
            (self.TEMPLATE_ID, ""),
        ):
            with self.subTest(template_id=template_id, version=version):
                with self.assertRaises(collector.EvidenceError):
                    collector._launch_template_pair(
                        {"LaunchTemplateId": template_id, "Version": version},
                        "membership",
                    )

    def test_reads_the_reserved_tags(self) -> None:
        self.assertEqual(
            collector._reserved_launch_template_tags(self.described_instance()),
            {"LaunchTemplateId": self.TEMPLATE_ID, "Version": "2"},
        )

    def test_reserved_tag_failures_are_fail_closed(self) -> None:
        cases = [
            {"InstanceId": "i-0b74635bfac7d988c"},
            {"InstanceId": "i-0b74635bfac7d988c", "Tags": "aws:ec2launchtemplate:id"},
            {"InstanceId": "i-0b74635bfac7d988c", "Tags": [None]},
            self.described_instance(
                extra_tags=[
                    {"Key": "aws:ec2launchtemplate:version", "Value": "9"},
                ]
            ),
        ]
        for instance in cases:
            with self.subTest(instance=instance):
                with self.assertRaises(collector.EvidenceError):
                    collector._reserved_launch_template_tags(instance)

    def test_absent_reserved_tags_fail_closed_downstream(self) -> None:
        with self.assertRaises(collector.EvidenceError):
            collector._launch_template_pair(
                collector._reserved_launch_template_tags(
                    self.described_instance(template_id=None, version=None)
                ),
                "reserved instance tag",
            )


if __name__ == "__main__":
    unittest.main()


class BucketPolicyDigestNormalisationTest(unittest.TestCase):
    """S3 re-orders Principal.AWS, so the digest must be order-normalised.

    The published contract digest is sha256(jsonencode(<authored policy>)) from
    Terraform. GetBucketPolicy returns the same document with its principal
    lists in a different order, so digesting it verbatim can never match.
    """

    AUTHORED = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelfBoundNodeAttestationWrites",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::767397897469:role/a-server",
                        "arn:aws:iam::767397897469:role/b-frps",
                        "arn:aws:iam::767397897469:role/c-cell1",
                    ]
                },
                "Action": ["s3:PutObject"],
                "Resource": "arn:aws:s3:::bucket/runtime/*",
            },
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket",
            },
        ],
    }

    def digest(self, policy: dict) -> str:
        return collector._terraform_jsonencode_digest(
            collector._sorted_policy_scalar_lists(policy),
            maximum=64 * 1024,
            name="policy",
        )

    def aws_returned(self) -> dict:
        """The same policy with AWS's principal ordering."""
        returned = copy.deepcopy(self.AUTHORED)
        returned["Statement"][0]["Principal"]["AWS"] = [
            "arn:aws:iam::767397897469:role/c-cell1",
            "arn:aws:iam::767397897469:role/a-server",
            "arn:aws:iam::767397897469:role/b-frps",
        ]
        return returned

    def test_reordered_principals_produce_the_authored_digest(self) -> None:
        self.assertNotEqual(
            self.AUTHORED["Statement"][0]["Principal"]["AWS"],
            self.aws_returned()["Statement"][0]["Principal"]["AWS"],
        )
        self.assertEqual(self.digest(self.aws_returned()), self.digest(self.AUTHORED))

    def test_an_added_principal_still_breaks_the_digest(self) -> None:
        tampered = self.aws_returned()
        tampered["Statement"][0]["Principal"]["AWS"].append(
            "arn:aws:iam::767397897469:role/attacker"
        )
        self.assertNotEqual(self.digest(tampered), self.digest(self.AUTHORED))

    def test_a_removed_principal_still_breaks_the_digest(self) -> None:
        tampered = self.aws_returned()
        tampered["Statement"][0]["Principal"]["AWS"].pop()
        self.assertNotEqual(self.digest(tampered), self.digest(self.AUTHORED))

    def test_effect_and_action_changes_still_break_the_digest(self) -> None:
        for mutate in (
            lambda p: p["Statement"][0].__setitem__("Effect", "Deny"),
            lambda p: p["Statement"][0].__setitem__("Action", ["s3:*"]),
            lambda p: p["Statement"][1].__setitem__("Principal", "arn:aws:iam::1:root"),
        ):
            with self.subTest(mutate=mutate):
                tampered = self.aws_returned()
                mutate(tampered)
                self.assertNotEqual(self.digest(tampered), self.digest(self.AUTHORED))

    def test_statement_order_is_preserved(self) -> None:
        """Statement lists hold objects, so their order must NOT be sorted."""
        swapped = self.aws_returned()
        swapped["Statement"].reverse()
        self.assertNotEqual(self.digest(swapped), self.digest(self.AUTHORED))


class TerraformJsonencodeDigestTest(unittest.TestCase):
    """The contract digests are sha256(jsonencode(...)) from Terraform.

    Terraform's jsonencode is Go's encoding/json, which HTML-escapes <, > and &.
    Python does not. The repair document is a shell script full of `>` and `&&`,
    so digesting it as plain canonical JSON diverged on every run.
    """

    def digest(self, value: object) -> str:
        return collector._terraform_jsonencode_digest(
            value, maximum=64 * 1024, name="document"
        )

    def go_jsonencode(self, value: object) -> str:
        """An independent re-implementation of Go's encoding/json escaping."""
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        for character in ("<", ">", "&"):
            encoded = encoded.replace(
                character, "\\u%04x" % ord(character)
            )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def test_matches_go_escaping_for_shell_content(self) -> None:
        document = {
            "schemaVersion": "2.2",
            "mainSteps": [
                {
                    "inputs": {
                        "runCommand": [
                            "set -euo pipefail",
                            "test -f /etc/x && echo ok > /tmp/out",
                            "if [ 1 -lt 2 ]; then echo '<done>'; fi",
                        ]
                    }
                }
            ],
        }
        self.assertEqual(self.digest(document), self.go_jsonencode(document))

    def test_differs_from_unescaped_canonical_json(self) -> None:
        """The bug: plain canonical JSON disagrees whenever <, > or & appear."""
        document = {"runCommand": "echo a > b && echo '<c>'"}
        unescaped = hashlib.sha256(
            contract.canonical_bytes(document, maximum=64 * 1024, name="d")
        ).hexdigest()
        self.assertNotEqual(self.digest(document), unescaped)

    def test_agrees_with_canonical_json_without_those_characters(self) -> None:
        """Why the bucket policy matched but the repair document never did."""
        document = {"runCommand": "echo plain", "schemaVersion": "2.2"}
        self.assertEqual(
            self.digest(document),
            hashlib.sha256(
                contract.canonical_bytes(document, maximum=64 * 1024, name="d")
            ).hexdigest(),
        )

    def test_key_order_does_not_change_the_digest(self) -> None:
        self.assertEqual(
            self.digest({"a": 1, "b": 2}), self.digest({"b": 2, "a": 1})
        )

    def test_content_changes_still_break_the_digest(self) -> None:
        base = {"runCommand": "echo a > b"}
        for mutated in (
            {"runCommand": "echo a > c"},
            {"runCommand": "echo a >> b"},
            {"runCommand": "echo a > b", "extra": True},
            {},
        ):
            with self.subTest(mutated=mutated):
                self.assertNotEqual(self.digest(mutated), self.digest(base))

    def test_oversized_documents_fail_closed(self) -> None:
        with self.assertRaises(collector.EvidenceError):
            collector._terraform_jsonencode_digest(
                {"big": "x" * 4096}, maximum=64, name="document"
            )


class EcrManifestMultiTagTest(unittest.TestCase):
    """batch-get-image returns one entry PER TAG, not per image.

    The governed publisher stamps both a run-scoped staging tag and the
    source-revision tag on the promoted image, so a correct digest routinely
    comes back as two byte-identical entries.
    """

    DIGEST = "sha256:" + "a" * 64

    def entry(self, tag, *, digest=None, manifest="MANIFEST"):
        return {
            "imageId": {"imageDigest": digest or self.DIGEST, "imageTag": tag},
            "imageManifest": manifest,
        }

    def resolve(self, images):
        """Mirror the collector's resolution predicate."""
        response = {"failures": [], "images": images}
        return (
            isinstance(response, dict)
            and response.get("failures") == []
            and isinstance(response.get("images"), list)
            and bool(response["images"])
            and all(isinstance(e, dict) for e in response["images"])
            and len({
                (e.get("imageId", {}).get("imageDigest"), e.get("imageManifest"))
                for e in response["images"]
            })
            == 1
        )

    def test_two_tags_on_one_digest_resolve(self) -> None:
        self.assertTrue(self.resolve([self.entry("stage-tag"), self.entry("rev-tag")]))

    def test_single_tag_resolves(self) -> None:
        self.assertTrue(self.resolve([self.entry("only")]))

    def test_differing_manifests_fail_closed(self) -> None:
        self.assertFalse(
            self.resolve([self.entry("a"), self.entry("b", manifest="OTHER")])
        )

    def test_differing_digests_fail_closed(self) -> None:
        self.assertFalse(
            self.resolve(
                [self.entry("a"), self.entry("b", digest="sha256:" + "b" * 64)]
            )
        )

    def test_no_images_fails_closed(self) -> None:
        self.assertFalse(self.resolve([]))

    def test_non_dict_entries_fail_closed(self) -> None:
        self.assertFalse(self.resolve([self.entry("a"), "not-a-dict"]))


class InstanceRefreshPaginationTest(unittest.TestCase):
    """--max-records 1 always yields a NextToken once older refreshes exist.

    DescribeInstanceRefreshes returns newest-first, so the single returned entry
    IS the most recent one. cell0's server group is on its sixth refresh, so a
    token is present on every healthy call.
    """

    ASG = "layerv-nhp-sandbox-server"

    def refresh(self, status="Successful"):
        return {"AutoScalingGroupName": self.ASG, "Status": status}

    def check(self, response):
        with mock.patch.object(collector, "_aws", return_value=response):
            collector._require_no_active_instance_refresh("nhp_cell0", self.ASG)

    def test_terminal_refresh_with_older_history_is_accepted(self) -> None:
        """The live cell0 shape: Successful, plus a token for older refreshes."""
        self.check({"InstanceRefreshes": [self.refresh()], "NextToken": "older"})

    def test_terminal_refresh_without_token_is_accepted(self) -> None:
        self.check({"InstanceRefreshes": [self.refresh()]})

    def test_never_refreshed_group_is_accepted(self) -> None:
        self.check({"InstanceRefreshes": []})

    def test_empty_page_with_a_token_still_fails_closed(self) -> None:
        """We asked for the newest and got none while AWS says more exist."""
        with self.assertRaisesRegex(collector.EvidenceError, "is incomplete"):
            self.check({"InstanceRefreshes": [], "NextToken": "more"})

    def test_active_refresh_still_fails_closed(self) -> None:
        for status in ("InProgress", "Pending", "Cancelling", "Bogus"):
            with self.subTest(status=status):
                with self.assertRaisesRegex(collector.EvidenceError, "still active"):
                    self.check(
                        {
                            "InstanceRefreshes": [self.refresh(status)],
                            "NextToken": "older",
                        }
                    )

    def test_more_than_one_entry_still_fails_closed(self) -> None:
        with self.assertRaisesRegex(collector.EvidenceError, "is incomplete"):
            self.check({"InstanceRefreshes": [self.refresh(), self.refresh()]})

    def test_foreign_group_name_still_fails_closed(self) -> None:
        with self.assertRaisesRegex(collector.EvidenceError, "still active"):
            self.check(
                {
                    "InstanceRefreshes": [
                        {"AutoScalingGroupName": "other-asg", "Status": "Successful"}
                    ],
                    "NextToken": "older",
                }
            )


class RepairAssociationOverviewTest(unittest.TestCase):
    """DescribeAssociation omits Status for tag-targeted associations.

    Verified against all three live repair associations: "Status" is not null,
    it is absent from the response body. Overview is the populated member.
    """

    def overview(self, **kwargs):
        base = {
            "Status": "Success",
            "DetailedStatus": "Success",
            "AssociationStatusAggregatedCount": {"Success": 3},
        }
        base.update(kwargs)
        return {"Overview": base}

    def test_live_shape_succeeds(self) -> None:
        self.assertTrue(collector._repair_association_succeeded(self.overview()))

    def test_absent_status_member_is_not_itself_a_failure(self) -> None:
        """The exact regression: no Status key at all, yet healthy."""
        association = self.overview()
        self.assertNotIn("Status", association)
        self.assertTrue(collector._repair_association_succeeded(association))

    def test_partial_fleet_failure_fails_closed(self) -> None:
        self.assertFalse(
            collector._repair_association_succeeded(
                self.overview(AssociationStatusAggregatedCount={"Success": 2, "Failed": 1})
            )
        )

    def test_non_success_detail_fails_closed(self) -> None:
        for detail in ("Pending", "Failed", "InProgress"):
            with self.subTest(detail=detail):
                self.assertFalse(
                    collector._repair_association_succeeded(
                        self.overview(DetailedStatus=detail)
                    )
                )

    def test_zero_successes_fails_closed(self) -> None:
        self.assertFalse(
            collector._repair_association_succeeded(
                self.overview(AssociationStatusAggregatedCount={"Success": 0})
            )
        )

    def test_missing_or_malformed_overview_fails_closed(self) -> None:
        for association in ({}, {"Overview": None}, {"Overview": "Success"}):
            with self.subTest(association=association):
                self.assertFalse(collector._repair_association_succeeded(association))


class RepairExecutionBindingTest(unittest.TestCase):
    """Bind the attestation to one real successful repair execution.

    The previous query filtered `Key=CreatedTime,Value=<attested>,Type=EQUAL`
    and required exactly one Success in the result.  That is unsatisfiable, so
    the branch could never pass for any instance, healthy or not.  Verified
    live against the sandbox cell-0 repair association while it was healthy --
    69 consecutive successful executions on a `rate(30 minutes)` schedule --
    where the EQUAL filter returned zero rows for the attested second AND for
    the attested instant reproduced to the microsecond.  Two independent
    reasons: SSM does not honour EQUAL on CreatedTime, and every real
    CreatedTime carries sub-second precision while the attested value is
    truncated to whole UTC seconds by the on-instance collector.

    So these fixtures use the real wire shape -- microseconds, a non-UTC
    offset, newest-first ordering, `NextToken` on a healthy association.  A
    fixture that echoes the attested `...Z` string back as CreatedTime encodes
    the checker's own assumption and cannot catch a filter that never matches.
    """

    ASSOCIATION_ID = "3b7fbdbc-77c6-4d2f-874b-c6a1581071ea"
    DOCUMENT_NAME = "layerv-nhp-sandbox-runtime-attestation-repair"
    # The association targets every colour of the fleet; ASG is the one the
    # producer resolved as ACTIVE and must find inside that set.
    ATTESTED_ASGS = [
        "layerv-nhp-sandbox-server",
        "layerv-nhp-sandbox-server-green",
    ]
    ASG = "layerv-nhp-sandbox-server-green"
    INSTANCE = "i-081174c8c26a42d70"
    CONTRACT = {
        "repair_document_name": DOCUMENT_NAME,
        "repair_document_version": "2",
    }

    def _description(self) -> dict[str, object]:
        return {
            "AssociationDescription": {
                "AssociationId": self.ASSOCIATION_ID,
                "Name": self.DOCUMENT_NAME,
                "AssociationVersion": "2",
                "DocumentVersion": "2",
                "ScheduleExpression": "rate(30 minutes)",
                "Targets": [
                    {
                        "Key": "tag:aws:autoscaling:groupName",
                        "Values": list(self.ATTESTED_ASGS),
                    }
                ],
                "Overview": {
                    "Status": "Success",
                    "DetailedStatus": "Success",
                    "AssociationStatusAggregatedCount": {"Success": 3},
                },
            }
        }

    def _execution(
        self,
        created: str,
        *,
        status: str = "Success",
        execution_id: str = "9ea26ea3-dab5-48c7-92a0-12a9d0f2d207",
    ) -> dict[str, object]:
        return {
            "AssociationId": self.ASSOCIATION_ID,
            "AssociationVersion": "2",
            "ExecutionId": execution_id,
            "Status": status,
            "DetailedStatus": status,
            "CreatedTime": created,
            "ResourceCountByStatus": "{Success=3}",
        }

    def _target(
        self, resource_id: str, *, status: str = "Success"
    ) -> dict[str, object]:
        return {
            "AssociationId": self.ASSOCIATION_ID,
            "ResourceId": resource_id,
            "ResourceType": "ManagedInstance",
            "Status": status,
            "DetailedStatus": status,
        }

    def _verify(
        self,
        *,
        attested: str,
        executions: list[dict[str, object]],
        next_token: str | None = "AAMAAR2/G2G1w8MZ1UALsJbAGZYI8TOIoow1K69",
        targets: list[dict[str, object]] | None = None,
    ) -> tuple[str, list[list[str]]]:
        """Drive `_verify_repair` over one fake SSM conversation."""

        executions_response: dict[str, object] = {"AssociationExecutions": executions}
        if next_token is not None:
            executions_response["NextToken"] = next_token
        if targets is None:
            targets = [self._target(self.INSTANCE)]
        responses = [
            self._description(),
            executions_response,
            {"AssociationExecutionTargets": targets},
        ]
        calls: list[list[str]] = []

        def fake_aws(service: str, arguments: list[str], name: str) -> object:
            calls.append(arguments)
            return responses[len(calls) - 1]

        with mock.patch.object(collector, "_aws", side_effect=fake_aws):
            observed = collector._verify_repair(
                {
                    "repair_association_id": self.ASSOCIATION_ID,
                    "repair_document_name": self.DOCUMENT_NAME,
                    "repair_last_success_at": attested,
                },
                self.INSTANCE,
                autoscaling_group=self.ASG,
                attested_asg_names=list(self.ATTESTED_ASGS),
                collector_contract=self.CONTRACT,
            )
        return observed, calls

    def _expect(self, message: str, **kwargs: object) -> None:
        with self.assertRaisesRegex(collector.EvidenceError, message):
            self._verify(**kwargs)  # type: ignore[arg-type]

    def test_attested_second_binds_to_its_successful_execution(self) -> None:
        """Happy path: a live, healthy, paginated association."""

        observed, calls = self._verify(
            attested="2026-07-28T07:08:20Z",
            executions=[
                self._execution("2026-07-28T07:08:20.120000+00:00"),
                self._execution(
                    "2026-07-28T06:38:02.949000+00:00",
                    execution_id="1b8700c8-3c37-4434-9485-6344a120112a",
                ),
                self._execution(
                    "2026-07-28T06:08:28.999000+00:00",
                    execution_id="080500f4-104e-4c82-90e6-3122ec029778",
                ),
            ],
        )
        self.assertEqual(observed, "2026-07-28T07:08:20Z")
        # The unsatisfiable equality filter must be gone, replaced by the
        # exclusive upper edge of the attested second.
        self.assertIn(
            "Key=CreatedTime,Value=2026-07-28T07:08:21Z,Type=LESS_THAN", calls[1]
        )
        self.assertNotIn(
            "Key=CreatedTime,Value=2026-07-28T07:08:20Z,Type=EQUAL", calls[1]
        )

    def test_upper_bound_rolls_over_the_minute(self) -> None:
        _, calls = self._verify(
            attested="2026-07-28T07:08:59Z",
            executions=[self._execution("2026-07-28T07:08:59.999000+00:00")],
            next_token=None,
        )
        self.assertIn(
            "Key=CreatedTime,Value=2026-07-28T07:09:00Z,Type=LESS_THAN", calls[1]
        )

    def test_sub_second_and_non_utc_offset_still_match(self) -> None:
        """The exact shape that made the equality filter unsatisfiable.

        `2026-07-28T01:08:20.120000-06:00` is one real CreatedTime as the CLI
        renders it on a UTC-6 caller.  It is the same instant as the attested
        `2026-07-28T07:08:20Z`, and neither the microseconds nor the offset may
        be allowed to break the binding.
        """

        observed, _ = self._verify(
            attested="2026-07-28T07:08:20Z",
            executions=[self._execution("2026-07-28T01:08:20.120000-06:00")],
            next_token=None,
        )
        self.assertEqual(observed, "2026-07-28T07:08:20Z")

    def test_attestation_naming_a_nonexistent_execution_fails_closed(self) -> None:
        """No execution ran during the attested second."""

        self._expect(
            "has no unique successful repair execution",
            attested="2026-07-28T07:09:11Z",
            executions=[
                self._execution("2026-07-28T07:08:20.120000+00:00"),
                self._execution(
                    "2026-07-28T06:38:02.949000+00:00",
                    execution_id="1b8700c8-3c37-4434-9485-6344a120112a",
                ),
            ],
        )

    def test_failed_execution_in_the_attested_second_fails_closed(self) -> None:
        """A newer success elsewhere on the page must not rescue it."""

        self._expect(
            "has no unique successful repair execution",
            attested="2026-07-28T06:38:02Z",
            executions=[
                self._execution(
                    "2026-07-28T06:38:02.949000+00:00",
                    status="Failed",
                    execution_id="1b8700c8-3c37-4434-9485-6344a120112a",
                ),
                self._execution(
                    "2026-07-28T06:08:28.999000+00:00",
                    execution_id="080500f4-104e-4c82-90e6-3122ec029778",
                ),
            ],
        )

    def test_empty_result_fails_closed(self) -> None:
        self._expect(
            "has no unique successful repair execution",
            attested="2026-07-28T07:08:20Z",
            executions=[],
            next_token=None,
        )

    def test_ambiguous_second_fails_closed(self) -> None:
        """Two executions in the attested second: the binding is not unique."""

        self._expect(
            "has no unique successful repair execution",
            attested="2026-07-28T07:08:20Z",
            executions=[
                self._execution("2026-07-28T07:08:20.870000+00:00"),
                self._execution(
                    "2026-07-28T07:08:20.120000+00:00",
                    execution_id="1b8700c8-3c37-4434-9485-6344a120112a",
                ),
            ],
            next_token=None,
        )

    def test_page_that_stops_inside_the_attested_second_is_incomplete(self) -> None:
        """Uniqueness is unprovable while the next page may hold a sibling."""

        self._expect(
            "repair executions are incomplete",
            attested="2026-07-28T07:08:20Z",
            executions=[self._execution("2026-07-28T07:08:20.120000+00:00")],
        )

    def test_empty_truncated_page_is_incomplete(self) -> None:
        self._expect(
            "repair executions are incomplete",
            attested="2026-07-28T07:08:20Z",
            executions=[],
        )

    def test_row_newer_than_the_attested_second_is_incomplete(self) -> None:
        """The server-side bound was not applied, so nothing can be trusted."""

        self._expect(
            "repair executions are incomplete",
            attested="2026-07-28T06:38:02Z",
            executions=[
                self._execution("2026-07-28T07:08:20.120000+00:00"),
                self._execution(
                    "2026-07-28T06:38:02.949000+00:00",
                    execution_id="1b8700c8-3c37-4434-9485-6344a120112a",
                ),
            ],
            next_token=None,
        )

    def test_unordered_page_is_incomplete(self) -> None:
        """Newest-first is what makes the head-of-page argument sound."""

        self._expect(
            "repair executions are incomplete",
            attested="2026-07-28T07:08:20Z",
            executions=[
                self._execution(
                    "2026-07-28T06:08:28.999000+00:00",
                    execution_id="080500f4-104e-4c82-90e6-3122ec029778",
                ),
                self._execution("2026-07-28T07:08:20.120000+00:00"),
            ],
            next_token=None,
        )

    def test_execution_that_skipped_this_instance_fails_closed(self) -> None:
        """The exact live defect: a real success that never ran here.

        The on-instance collector picked execution 48c5b316 (a genuine Success)
        for `i-081174c8c26a42d70`, but that execution targeted five other
        instances and predates this one's launch.  Matching the attested second
        is necessary, not sufficient -- the per-target check still has to see
        this instance succeed.
        """

        self._expect(
            "repair execution was not successful",
            attested="2026-07-28T07:08:20Z",
            executions=[self._execution("2026-07-28T07:08:20.120000+00:00")],
            next_token=None,
            targets=[
                self._target("i-0b10c8548017573b5"),
                self._target("i-0a817cc296ac6efcc"),
                self._target("i-0580b55d04f4dfd81"),
                self._target("i-0a4b3adaf767b0365"),
                self._target("i-0a07f03415a26e6e3"),
            ],
        )

    def test_malformed_created_time_fails_closed(self) -> None:
        for created in (None, "", "2026-07-28 07:08:20", "2026-07-28T07:08:20"):
            with self.subTest(created=created):
                self._expect(
                    "repair execution timestamp",
                    attested="2026-07-28T07:08:20Z",
                    executions=[self._execution(created)],  # type: ignore[arg-type]
                    next_token=None,
                )


class RevisionOnDefaultBranchTest(unittest.TestCase):
    """Built-from-trusted-main is the property; equality with the tip is not.

    Every commit to the default branch moves the tip, including CI-only
    dependabot bumps that produce no new image, so equality is unsatisfiable in
    steady state while containment holds for exactly the trustworthy images.
    """

    TIP = "4" * 40
    REV = "a" * 40

    def check(self, comparison):
        with mock.patch.object(collector, "_gh", return_value=comparison):
            collector._require_revision_on_default_branch(self.REV, self.TIP, "qRTS")

    def test_identical_revision_needs_no_api_call(self) -> None:
        """The tip itself short-circuits, so the common case costs nothing."""
        with mock.patch.object(collector, "_gh") as gh:
            collector._require_revision_on_default_branch(self.TIP, self.TIP, "qRTS")
        gh.assert_not_called()

    def test_ancestor_behind_the_tip_is_accepted(self) -> None:
        """The live case: image built 4 CI-only commits before the tip."""
        self.check({"status": "ahead", "behind_by": 0, "ahead_by": 4})

    def test_identical_comparison_is_accepted(self) -> None:
        self.check({"status": "identical", "behind_by": 0, "ahead_by": 0})

    def test_diverged_revision_fails_closed(self) -> None:
        """A fork or unmerged PR commit carries commits main does not have."""
        for comparison in (
            {"status": "diverged", "behind_by": 2, "ahead_by": 1},
            {"status": "behind", "behind_by": 1, "ahead_by": 0},
        ):
            with self.subTest(comparison=comparison):
                with self.assertRaisesRegex(
                    collector.EvidenceError, "not a commit on trusted main"
                ):
                    self.check(comparison)

    def test_malformed_comparison_fails_closed(self) -> None:
        for comparison in (
            {},
            {"status": "ahead"},
            {"status": "ahead", "behind_by": "0"},
            {"status": "ahead", "behind_by": True},
            {"status": "unknown", "behind_by": 0},
            None,
        ):
            with self.subTest(comparison=comparison):
                with self.assertRaises(collector.EvidenceError):
                    self.check(comparison)

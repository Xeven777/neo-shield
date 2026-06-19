"""Read-only AWS configuration checks.

Only the checks in the specification are implemented: IAM broad permissions,
S3 public access indicators, EC2 unrestricted ingress and selected CloudTrail
management events. Credentials come from Boto3's normal credential chain or an
explicit local profile; they are never accepted from, or returned to, the web
app. No AWS resource is created, changed or deleted.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from neoshield.config import Settings
from neoshield.worker.normalize import Finding, clip, safe_evidence

logger = logging.getLogger(__name__)

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")

AWS_TOOLS = ["aws-iam", "aws-s3", "aws-ec2", "aws-cloudtrail"]

PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

HIGH_SIGNAL_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "CreateSecurityGroup",
    "DeleteSecurityGroup",
    "RevokeSecurityGroupIngress",
    "PutBucketAcl",
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketPublicAccessBlock",
    "DeleteBucketPublicAccessBlock",
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "CreateRole",
    "DeleteRole",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "DeleteRolePolicy",
    "CreateAccessKey",
    "DeleteAccessKey",
    "DeactivateMFADevice",
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
}


class AwsScanError(RuntimeError):
    """AWS could not be inspected safely."""


class AwsScopeError(ValueError):
    """The requested account or region scope is invalid."""


@dataclass(slots=True)
class AwsScanOutcome:
    findings: list[Finding]
    snapshot: dict[str, Any]
    tools: list[dict[str, Any]] = field(default_factory=list)


def validate_scope(
    account_id: str, regions: list[str], settings: Settings
) -> tuple[str, list[str]]:
    normalized_account = (account_id or "").strip()
    if not ACCOUNT_ID_PATTERN.fullmatch(normalized_account):
        raise AwsScopeError("A 12-digit AWS account id is required")

    normalized_regions = sorted(
        {(region or "").strip().lower() for region in regions if region}
    )
    if not normalized_regions:
        raise AwsScopeError("At least one AWS region is required")
    if len(normalized_regions) > settings.aws_max_regions:
        raise AwsScopeError(
            f"At most {settings.aws_max_regions} AWS regions can be checked"
        )
    for region in normalized_regions:
        if not REGION_PATTERN.fullmatch(region):
            raise AwsScopeError(f"Invalid AWS region: {region}")

    return normalized_account, normalized_regions


# ---------------------------------------------------------------------------
# Pure policy and finding helpers (unit tested without AWS calls)
# ---------------------------------------------------------------------------


def _as_list(value: object) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def decode_document(document: object) -> dict[str, Any]:
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            decoded = urllib.parse.unquote(document)
            parsed = json.loads(decoded)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, json.JSONDecodeError):
            return {}
    return {}


def policy_statements(document: object) -> list[dict[str, Any]]:
    decoded = decode_document(document)
    return [
        statement
        for statement in _as_list(decoded.get("Statement"))
        if isinstance(statement, dict)
    ]


def statement_is_broad(statement: dict[str, Any]) -> bool:
    if str(statement.get("Effect", "Allow")).lower() != "allow":
        return False

    resources = _as_list(statement.get("Resource"))
    resource_broad = any(str(resource) == "*" for resource in resources)

    if _as_list(statement.get("NotAction")):
        return resource_broad

    actions = [str(action) for action in _as_list(statement.get("Action"))]
    action_broad = any(
        action == "*" or (action.endswith(":*") and action.count(":") == 1)
        for action in actions
    )
    return action_broad and resource_broad


def policy_is_broad(document: object) -> bool:
    return any(
        statement_is_broad(statement) for statement in policy_statements(document)
    )


def unrestricted_cidrs(permission: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for entry in _as_list(permission.get("IpRanges")):
        if isinstance(entry, dict) and entry.get("CidrIp") in {
            "0.0.0.0/0",
            "::/0",
        }:
            cidrs.append(str(entry["CidrIp"]))
    for entry in _as_list(permission.get("Ipv6Ranges")):
        if isinstance(entry, dict) and entry.get("CidrIpv6") == "::/0":
            cidrs.append("::/0")
    return sorted(set(cidrs))


def _port_range(permission: dict[str, Any]) -> tuple[int, int]:
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return (-1, -1)
    return (from_port, to_port)


def ingress_severity(
    protocol: str, from_port: int, to_port: int
) -> tuple[str, str]:
    if from_port <= 22 <= to_port:
        return ("high", "SSH is reachable from the internet")
    if from_port <= 3389 <= to_port:
        return ("high", "RDP is reachable from the internet")
    if protocol == "-1" or (from_port <= 0 and to_port >= 65535):
        return ("critical", "All traffic is reachable from the internet")
    return ("medium", "An unrestricted ingress rule exposes this port range")


def security_group_findings(
    group: dict[str, Any], *, region: str
) -> list[Finding]:
    findings: list[Finding] = []
    group_id = str(group.get("GroupId") or "unknown")
    group_name = str(group.get("GroupName") or group_id)

    for permission in _as_list(group.get("IpPermissions")):
        if not isinstance(permission, dict):
            continue
        protocol = str(permission.get("IpProtocol") or "-1")
        from_port, to_port = _port_range(permission)
        for cidr in unrestricted_cidrs(permission):
            severity, reason = ingress_severity(protocol, from_port, to_port)
            stable_key = (
                f"aws|ec2|{region}|{group_id}|ingress|"
                f"{protocol}|{from_port}|{to_port}|{cidr}"
            )
            findings.append(
                Finding(
                    source="aws",
                    source_tool="aws-ec2",
                    source_rule_id="ec2-unrestricted-ingress",
                    stable_key=stable_key,
                    title=f"Security group {group_name} allows {cidr} ingress",
                    description=f"{reason}. Review whether this rule is required.",
                    category="aws_network",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high",
                    remediation=(
                        "Restrict the source range or remove the rule after "
                        "confirming the workload does not depend on it."
                    ),
                    evidence=safe_evidence(
                        {
                            "region": region,
                            "groupId": group_id,
                            "groupName": group_name,
                            "protocol": protocol,
                            "fromPort": from_port,
                            "toPort": to_port,
                            "cidr": cidr,
                        }
                    ),
                )
            )
    return findings


def public_access_findings(
    bucket: str, *, block: dict[str, Any] | None, public_policy: bool, public_acl: bool
) -> list[Finding]:
    findings: list[Finding] = []

    if block is None or not all(
        block.get(key) is True
        for key in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    ):
        findings.append(
            Finding(
                source="aws",
                source_tool="aws-s3",
                source_rule_id="s3-public-access-block",
                stable_key=f"aws|s3|{bucket}|public-access-block",
                title=f"S3 bucket {bucket} does not block all public access",
                description=(
                    "At least one S3 public-access-block setting is missing or "
                    "disabled. This is a review item, not proof of exposure."
                ),
                category="aws_storage",
                severity="medium",
                confidence="high",
                remediation=(
                    "Enable all four S3 Block Public Access settings unless a "
                    "documented public bucket is required."
                ),
                evidence=safe_evidence(
                    {"bucket": bucket, "publicAccessBlock": block}
                ),
            )
        )

    if public_policy:
        findings.append(
            Finding(
                source="aws",
                source_tool="aws-s3",
                source_rule_id="s3-public-policy",
                stable_key=f"aws|s3|{bucket}|public-policy",
                title=f"S3 bucket {bucket} has a public bucket policy",
                description=(
                    "S3 reports that the current bucket policy makes the bucket "
                    "public. Review the policy and intended audience."
                ),
                category="aws_storage",
                severity="high",
                confidence="high",
                remediation="Remove public principals or scope the policy tightly.",
                evidence=safe_evidence({"bucket": bucket, "publicPolicy": True}),
            )
        )

    if public_acl:
        findings.append(
            Finding(
                source="aws",
                source_tool="aws-s3",
                source_rule_id="s3-public-acl",
                stable_key=f"aws|s3|{bucket}|public-acl",
                title=f"S3 bucket {bucket} grants access to a public group",
                description=(
                    "The bucket ACL grants permissions to AllUsers or "
                    "AuthenticatedUsers."
                ),
                category="aws_storage",
                severity="high",
                confidence="high",
                remediation="Remove public ACL grants and enable Block Public Access.",
                evidence=safe_evidence({"bucket": bucket, "publicAcl": True}),
            )
        )

    return findings


def broad_policy_findings(
    *, principal_type: str, principal_name: str, policy_names: list[str]
) -> list[Finding]:
    if not policy_names:
        return []
    return [
        Finding(
            source="aws",
            source_tool="aws-iam",
            source_rule_id="iam-broad-permission",
            stable_key=f"aws|iam|{principal_type}|{principal_name}|broad",
            title=f"IAM {principal_type} {principal_name} has broad permissions",
            description=(
                "An attached or inline policy allows a wildcard action on all "
                "resources. Treat this as a least-privilege review item."
            ),
            category="aws_iam",
            severity="high",
            confidence="medium",
            remediation=(
                "Replace wildcard actions/resources with the minimum permissions "
                "the principal actually uses."
            ),
            evidence=safe_evidence(
                {
                    "principalType": principal_type,
                    "principalName": principal_name,
                    "policies": policy_names[:20],
                }
            ),
        )
    ]


# ---------------------------------------------------------------------------
# AWS API collection
# ---------------------------------------------------------------------------


def _error_summary(error: Exception) -> str:
    if isinstance(error, ClientError):
        detail = error.response.get("Error", {})
        return clip(
            f"{detail.get('Code', 'ClientError')}: "
            f"{detail.get('Message', 'AWS request failed')}",
            300,
        )
    return clip(f"{type(error).__name__}: {error}", 300)


def _tool_result(
    name: str, status: str, finding_count: int, started: float, error: str | None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "version": boto3.__version__,
        "status": status,
        "findingCount": finding_count,
        "durationMs": int((time.monotonic() - started) * 1000),
    }
    if error:
        result["error"] = error
    return result


def _paginate(client: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
    paginator = client.get_paginator(operation)
    items: list[Any] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def _managed_policy_document(iam: Any, policy_arn: str) -> dict[str, Any]:
    policy = iam.get_policy(PolicyArn=policy_arn).get("Policy", {})
    version_id = policy.get("DefaultVersionId")
    if not version_id:
        return {}
    version = iam.get_policy_version(
        PolicyArn=policy_arn, VersionId=version_id
    ).get("PolicyVersion", {})
    return decode_document(version.get("Document"))


def collect_iam(session: Any, settings: Settings) -> list[Finding]:
    iam = session.client("iam")
    findings: list[Finding] = []
    cache: dict[str, dict[str, Any]] = {}

    def policy_is_broad_cached(arn: str) -> bool:
        if arn not in cache:
            cache[arn] = _managed_policy_document(iam, arn)
        return policy_is_broad(cache[arn])

    users = _paginate(iam, "list_users", "Users")[: settings.aws_max_items]
    for user in users:
        if not isinstance(user, dict):
            continue
        name = str(user.get("UserName") or "")
        if not name:
            continue
        names: list[str] = []
        if any(
            policy_is_broad_cached(str(policy.get("PolicyArn")))
            for policy in iam.list_attached_user_policies(UserName=name).get(
                "AttachedPolicies", []
            )
            if isinstance(policy, dict) and policy.get("PolicyArn")
        ):
            names.append("attached-managed-policy")
        for policy_name in iam.list_user_policies(UserName=name).get(
            "PolicyNames", []
        ):
            document = iam.get_user_policy(
                UserName=name, PolicyName=policy_name
            ).get("PolicyDocument", {})
            if policy_is_broad(document):
                names.append(str(policy_name))
        findings.extend(
            broad_policy_findings(
                principal_type="user", principal_name=name, policy_names=names
            )
        )

    roles = _paginate(iam, "list_roles", "Roles")[: settings.aws_max_items]
    for role in roles:
        if not isinstance(role, dict):
            continue
        name = str(role.get("RoleName") or "")
        if not name:
            continue
        names = []
        if any(
            policy_is_broad_cached(str(policy.get("PolicyArn")))
            for policy in iam.list_attached_role_policies(RoleName=name).get(
                "AttachedPolicies", []
            )
            if isinstance(policy, dict) and policy.get("PolicyArn")
        ):
            names.append("attached-managed-policy")
        for policy_name in iam.list_role_policies(RoleName=name).get(
            "PolicyNames", []
        ):
            document = iam.get_role_policy(
                RoleName=name, PolicyName=policy_name
            ).get("PolicyDocument", {})
            if policy_is_broad(document):
                names.append(str(policy_name))
        findings.extend(
            broad_policy_findings(
                principal_type="role", principal_name=name, policy_names=names
            )
        )

    return findings


def collect_s3(session: Any, settings: Settings) -> list[Finding]:
    s3 = session.client("s3")
    findings: list[Finding] = []
    buckets = s3.list_buckets().get("Buckets", [])[: settings.aws_max_items]

    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        name = str(bucket.get("Name") or "")
        if not name:
            continue

        block: dict[str, Any] | None = None
        try:
            block = s3.get_public_access_block(Bucket=name).get(
                "PublicAccessBlockConfiguration"
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in {
                "NoSuchPublicAccessBlockConfiguration",
                "NoSuchPublicAccessBlock",
            }:
                raise

        public_policy = False
        try:
            public_policy = bool(
                s3.get_bucket_policy_status(Bucket=name)
                .get("PolicyStatus", {})
                .get("IsPublic")
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                raise

        public_acl = False
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        public_acl = any(
            isinstance(grant, dict)
            and grant.get("Grantee", {}).get("URI") in PUBLIC_ACL_URIS
            for grant in grants
        )
        findings.extend(
            public_access_findings(
                name,
                block=block if isinstance(block, dict) else None,
                public_policy=public_policy,
                public_acl=public_acl,
            )
        )

    return findings


def collect_ec2(
    session: Any, region: str, settings: Settings
) -> list[Finding]:
    ec2 = session.client("ec2", region_name=region)
    groups = _paginate(ec2, "describe_security_groups", "SecurityGroups")[
        : settings.aws_max_items
    ]
    findings: list[Finding] = []
    for group in groups:
        if isinstance(group, dict):
            findings.extend(security_group_findings(group, region=region))
    return findings


def collect_cloudtrail(
    session: Any, region: str, settings: Settings
) -> list[Finding]:
    cloudtrail = session.client("cloudtrail", region_name=region)
    start_time = datetime.now(UTC) - timedelta(
        hours=settings.aws_cloudtrail_lookback_hours
    )
    findings: list[Finding] = []
    max_events = min(settings.aws_cloudtrail_max_events, settings.aws_max_items)
    token: str | None = None

    while len(findings) < max_events:
        kwargs: dict[str, Any] = {
            "StartTime": start_time,
            "MaxResults": min(50, max_events - len(findings)),
        }
        if token:
            kwargs["NextToken"] = token
        response = cloudtrail.lookup_events(**kwargs)
        events = response.get("Events", [])
        for event in events:
            if not isinstance(event, dict):
                continue
            name = str(event.get("EventName") or "")
            if name not in HIGH_SIGNAL_EVENTS:
                continue
            event_id = str(event.get("EventId") or "")
            if not event_id:
                continue
            findings.append(
                Finding(
                    source="aws",
                    source_tool="aws-cloudtrail",
                    source_rule_id="cloudtrail-high-signal-change",
                    stable_key=f"aws|cloudtrail|{region}|{event_id}",
                    title=f"CloudTrail recorded {name} in {region}",
                    description=(
                        "A selected high-signal management event was recorded. "
                        "Review the actor, source and affected resource."
                    ),
                    category="aws_audit",
                    severity="medium",
                    confidence="high",
                    remediation=(
                        "Confirm the change was expected and that the principal "
                        "still has only the permissions it needs."
                    ),
                    evidence=safe_evidence(
                        {
                            "region": region,
                            "eventName": name,
                            "eventTime": str(event.get("EventTime") or ""),
                            "username": event.get("Username"),
                            "sourceIpAddress": event.get("SourceIPAddress"),
                            "resource": [
                                resource.get("ResourceName")
                                for resource in _as_list(
                                    event.get("Resources")
                                )
                                if isinstance(resource, dict)
                            ][:10],
                        }
                    ),
                )
            )
            if len(findings) >= max_events:
                break
        token = response.get("NextToken")
        if not token or not events:
            break

    return findings


def scan_aws(
    *,
    account_id: str,
    regions: list[str],
    profile: str | None,
    settings: Settings,
) -> AwsScanOutcome:
    if not settings.aws_enabled:
        raise AwsScanError("AWS scanning is disabled on this worker")

    account_id, regions = validate_scope(account_id, regions, settings)
    selected_profile = (profile or "").strip() or settings.aws_profile

    try:
        session = boto3.Session(
            profile_name=selected_profile or None, region_name=regions[0]
        )
        identity = session.client("sts").get_caller_identity()
    except (ClientError, BotoCoreError) as error:
        raise AwsScanError(
            f"AWS credentials are unavailable: {_error_summary(error)}"
        ) from error

    actual_account = str(identity.get("Account") or "")
    if actual_account != account_id:
        raise AwsScanError(
            "The resolved AWS credentials belong to a different account than "
            "the authorized asset"
        )

    findings: list[Finding] = []
    tools: list[dict[str, Any]] = []

    checks: list[tuple[str, Any]] = [
        ("aws-iam", lambda: collect_iam(session, settings)),
        ("aws-s3", lambda: collect_s3(session, settings)),
    ]

    for name, check in checks:
        started = time.monotonic()
        try:
            produced = check()
        except (ClientError, BotoCoreError) as error:
            tools.append(
                _tool_result(name, "error", 0, started, _error_summary(error))
            )
            logger.warning("%s check failed: %s", name, _error_summary(error))
            continue
        findings.extend(produced)
        tools.append(_tool_result(name, "ok", len(produced), started, None))

    for name, collector in (
        ("aws-ec2", collect_ec2),
        ("aws-cloudtrail", collect_cloudtrail),
    ):
        started = time.monotonic()
        produced: list[Finding] = []
        errors: list[str] = []
        for region in regions:
            try:
                produced.extend(collector(session, region, settings))
            except (ClientError, BotoCoreError) as error:
                errors.append(f"{region}: {_error_summary(error)}")
                logger.warning("%s check failed in %s: %s", name, region, error)
        findings.extend(produced)
        tools.append(
            _tool_result(
                name,
                "error" if errors else "ok",
                len(produced),
                started,
                "; ".join(errors)[:300] if errors else None,
            )
        )

    snapshot = {
        "accountId": account_id,
        "regions": regions,
        "profile": selected_profile or "credential-chain",
        "checks": AWS_TOOLS,
        "findingCount": len(findings),
    }
    return AwsScanOutcome(findings=findings, snapshot=snapshot, tools=tools)

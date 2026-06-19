from __future__ import annotations

import pytest

from neoshield.config import Settings
from neoshield.worker import aws_scan
from neoshield.worker.aws_scan import (
    AwsScanError,
    AwsScopeError,
    broad_policy_findings,
    policy_is_broad,
    public_access_findings,
    scan_aws,
    security_group_findings,
    validate_scope,
)

ACCOUNT = "123456789012"


def settings() -> Settings:
    return Settings(aws_enabled=True, aws_max_regions=3, aws_max_items=50)


def test_scope_accepts_account_and_sorts_regions() -> None:
    account_id, regions = validate_scope(
        ACCOUNT, ["us-west-2", "us-east-1", "us-east-1"], settings()
    )
    assert account_id == ACCOUNT
    assert regions == ["us-east-1", "us-west-2"]


@pytest.mark.parametrize(
    ("account_id", "regions"),
    [
        ("123", ["us-east-1"]),
        ("12345678901a", ["us-east-1"]),
        (ACCOUNT, []),
        (ACCOUNT, ["not-a-region"]),
        (ACCOUNT, ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1"]),
    ],
)
def test_scope_rejects_invalid_input(account_id: str, regions: list[str]) -> None:
    with pytest.raises(AwsScopeError):
        validate_scope(account_id, regions, settings())


def test_broad_policy_detects_wildcards() -> None:
    assert policy_is_broad(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
    )
    assert policy_is_broad(
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            }
        }
    )
    assert policy_is_broad(
        {"Statement": {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}}
    )


def test_broad_policy_ignores_scoped_or_denied_statements() -> None:
    assert not policy_is_broad(
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example/*",
            }
        }
    )
    assert not policy_is_broad(
        {"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}}
    )


def test_security_group_findings_separate_ssh_and_all_traffic() -> None:
    findings = security_group_findings(
        {
            "GroupId": "sg-123",
            "GroupName": "lab",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                },
            ],
        },
        region="us-east-1",
    )

    assert [finding.source for finding in findings] == ["aws", "aws"]
    assert {finding.severity for finding in findings} == {"high", "critical"}
    assert all("0.0.0.0/0" in finding.evidence["cidr"] for finding in findings)
    assert all(finding.source_tool == "aws-ec2" for finding in findings)


def test_security_group_findings_include_ipv6() -> None:
    findings = security_group_findings(
        {
            "GroupId": "sg-456",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        },
        region="eu-west-1",
    )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].evidence["cidr"] == "::/0"
    assert "eu-west-1" in findings[0].stable_key


def test_public_access_findings_flag_missing_block_and_public_policy() -> None:
    findings = public_access_findings(
        "example-bucket", block=None, public_policy=True, public_acl=False
    )
    keys = {finding.stable_key for finding in findings}
    assert "aws|s3|example-bucket|public-access-block" in keys
    assert "aws|s3|example-bucket|public-policy" in keys


def test_public_access_findings_clear_when_all_controls_are_enabled() -> None:
    findings = public_access_findings(
        "example-bucket",
        block={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        public_policy=False,
        public_acl=False,
    )
    assert findings == []


def test_broad_policy_findings_are_deterministic() -> None:
    findings = broad_policy_findings(
        principal_type="role",
        principal_name="deploy-role",
        policy_names=["deploy-policy"],
    )
    assert len(findings) == 1
    assert findings[0].stable_key == "aws|iam|role|deploy-role|broad"
    assert findings[0].source_tool == "aws-iam"


class FakePaginator:
    def __init__(self, items: list[dict[str, object]] | None = None) -> None:
        self.items = items or []

    def paginate(self, **_kwargs):
        yield {"Users": self.items, "Roles": self.items, "SecurityGroups": self.items}


class FakeClient:
    def __init__(self, name: str) -> None:
        self.name = name

    def get_paginator(self, _operation: str) -> FakePaginator:
        return FakePaginator()

    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": ACCOUNT}

    def list_buckets(self) -> dict[str, object]:
        return {"Buckets": []}

    def lookup_events(self, **_kwargs) -> dict[str, object]:
        return {"Events": []}


class FakeSession:
    def __init__(self, **_kwargs) -> None:
        pass

    def client(self, name: str, **_kwargs) -> FakeClient:
        return FakeClient(name)


def test_scan_aws_uses_mocked_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aws_scan.boto3, "Session", FakeSession)

    outcome = scan_aws(
        account_id=ACCOUNT,
        regions=["us-east-1"],
        profile=None,
        settings=settings(),
    )

    assert outcome.findings == []
    assert outcome.snapshot["accountId"] == ACCOUNT
    assert {tool["name"] for tool in outcome.tools} == set(aws_scan.AWS_TOOLS)
    assert all(tool["status"] == "ok" for tool in outcome.tools)


def test_scan_aws_rejects_a_different_account(monkeypatch: pytest.MonkeyPatch) -> None:
    class WrongAccountSession(FakeSession):
        def client(self, name: str, **_kwargs) -> FakeClient:
            client = FakeClient(name)
            if name == "sts":
                client.get_caller_identity = lambda: {"Account": "999999999999"}  # type: ignore[method-assign]
            return client

    monkeypatch.setattr(aws_scan.boto3, "Session", WrongAccountSession)

    with pytest.raises(AwsScanError, match="different account"):
        scan_aws(
            account_id=ACCOUNT,
            regions=["us-east-1"],
            profile=None,
            settings=settings(),
        )

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from src.config import (
    ScannerConfig,
    CloudProvider,
    SeverityLevel,
    ComplianceStatus,
    ComplianceRule,
    Finding,
    ScanResult,
)


@pytest.fixture
def mock_aws_config():
    return ScannerConfig(
        enabled_providers=[CloudProvider.AWS],
        aws_regions=["us-east-1", "us-west-2"],
        severity_threshold=SeverityLevel.LOW,
        batch_size=100,
        timeout_seconds=300,
        parallel_scans=10,
        dry_run=True,
        verbose=True,
    )


@pytest.fixture
def mock_azure_config():
    return ScannerConfig(
        enabled_providers=[CloudProvider.AZURE],
        azure_subscriptions=["sub-123"],
        severity_threshold=SeverityLevel.HIGH,
        dry_run=True,
    )


@pytest.fixture
def mock_gcp_config():
    return ScannerConfig(
        enabled_providers=[CloudProvider.GCP],
        gcp_projects=["project-123"],
        severity_threshold=SeverityLevel.MEDIUM,
        dry_run=True,
    )


@pytest.fixture
def sample_s3_bucket_resource():
    return {
        "Id": "arn:aws:s3:::test-bucket",
        "Name": "test-bucket",
        "ResourceType": "AWS::S3::Bucket",
        "Region": "us-east-1",
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }


@pytest.fixture
def sample_security_group_resource():
    return {
        "Id": "sg-12345678",
        "Name": "test-sg",
        "ResourceType": "AWS::EC2::SecurityGroup",
        "VpcId": "vpc-123",
        "Region": "us-east-1",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }


@pytest.fixture
def sample_ebs_volume_resource():
    return {
        "Id": "vol-12345678",
        "Name": "test-volume",
        "ResourceType": "AWS::EC2::Volume",
        "Region": "us-east-1",
        "Encrypted": False,
        "VolumeType": "gp2",
    }


@pytest.fixture
def sample_rds_instance_resource():
    return {
        "Id": "db-12345678",
        "Name": "test-db",
        "ResourceType": "AWS::RDS::DBInstance",
        "Region": "us-east-1",
        "PubliclyAccessible": True,
        "StorageEncrypted": False,
    }


@pytest.fixture
def sample_terraform_resource():
    return {
        "Id": "aws_s3_bucket.example",
        "Name": "example",
        "ResourceType": "aws_s3_bucket",
        "SourceFile": "main.tf",
        "versioning": {"enabled": False},
        "logging": {},
    }


@pytest.fixture
def sample_kubernetes_pod_resource():
    return {
        "Id": "default/test-pod",
        "Name": "test-pod",
        "Namespace": "default",
        "ResourceType": "kubernetes.Pod",
        "PodSpec": {
            "containers": [
                {
                    "name": "main",
                    "securityContext": {
                        "privileged": True,
                        "readOnlyRootFilesystem": False,
                    },
                }
            ]
        },
    }


@pytest.fixture
def sample_finding():
    return Finding(
        finding_id="finding-123",
        rule_id="EC2-1",
        resource_id="sg-12345678",
        resource_type="AWS::EC2::SecurityGroup",
        resource_name="open-sg",
        status=ComplianceStatus.NON_COMPLIANT,
        severity=SeverityLevel.CRITICAL,
        message="Security group allows unrestricted SSH access",
        remediation="Modify security group to restrict SSH access to specific IP ranges",
        evidence={
            "resource": {
                "Id": "sg-12345678",
                "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            }
        },
        timestamp=datetime.utcnow(),
        cloud_provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="123456789012",
    )


@pytest.fixture
def sample_scan_result():
    findings = [
        Finding(
            finding_id="finding-1",
            rule_id="EC2-1",
            resource_id="sg-1",
            resource_type="AWS::EC2::SecurityGroup",
            resource_name="sg-1",
            status=ComplianceStatus.NON_COMPLIANT,
            severity=SeverityLevel.CRITICAL,
            message="Test violation",
            remediation="Fix it",
            evidence={},
            timestamp=datetime.utcnow(),
            cloud_provider=CloudProvider.AWS,
        ),
        Finding(
            finding_id="finding-2",
            rule_id="EC2-2",
            resource_id="vol-1",
            resource_type="AWS::EC2::Volume",
            resource_name="vol-1",
            status=ComplianceStatus.NON_COMPLIANT,
            severity=SeverityLevel.HIGH,
            message="EBS not encrypted",
            remediation="Enable encryption",
            evidence={},
            timestamp=datetime.utcnow(),
            cloud_provider=CloudProvider.AWS,
        ),
    ]

    return ScanResult(
        scan_id="scan-123456",
        timestamp=datetime.utcnow(),
        cloud_provider=CloudProvider.AWS,
        total_resources=10,
        scanned_resources=10,
        findings=findings,
        summary={
            "total_findings": 2,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "compliant": 8,
        },
        duration_seconds=5.5,
        rules_applied=["EC2-1", "EC2-2"],
    )


@pytest.fixture
def mock_boto3_session():
    with patch("boto3.Session") as mock:
        mock_session = Mock()
        mock.return_value = mock_session
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        yield mock, mock_session, mock_client


@pytest.fixture
def mock_s3_client():
    with patch("boto3.client") as mock:
        client = Mock()
        mock.return_value = client
        yield client


@pytest.fixture
def mock_ec2_client():
    with patch("boto3.client") as mock:
        client = Mock()
        mock.return_value = client
        yield client

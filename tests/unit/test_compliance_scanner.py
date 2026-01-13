import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.config import (
    ScannerConfig,
    CloudProvider,
    SeverityLevel,
    ComplianceStatus,
    ComplianceRule,
    Finding,
    ScanResult,
)
from src.rule_engine import (
    RuleEngine,
    AWSComplianceChecker,
    AzureComplianceChecker,
    GCPComplianceChecker,
    KubernetesComplianceChecker,
    TerraformComplianceChecker,
)


class TestConfig:
    def test_scanner_config_defaults(self):
        config = ScannerConfig()

        assert config.enabled_providers == []
        assert config.aws_regions == ["us-east-1", "us-west-2", "eu-west-1"]
        assert config.severity_threshold == SeverityLevel.LOW
        assert config.batch_size == 100
        assert config.timeout_seconds == 300
        assert config.parallel_scans == 10
        assert config.dry_run is False

    def test_scanner_config_custom(self):
        config = ScannerConfig(
            enabled_providers=[CloudProvider.AWS, CloudProvider.AZURE],
            aws_regions=["us-west-2"],
            severity_threshold=SeverityLevel.HIGH,
            batch_size=50,
        )

        assert len(config.enabled_providers) == 2
        assert "us-west-2" in config.aws_regions
        assert config.severity_threshold == SeverityLevel.HIGH
        assert config.batch_size == 50

    def test_cloud_provider_enum(self):
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.AZURE.value == "azure"
        assert CloudProvider.GCP.value == "gcp"
        assert CloudProvider.KUBERNETES.value == "kubernetes"
        assert CloudProvider.TERRAFORM.value == "terraform"

    def test_severity_level_enum(self):
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.INFO.value == "info"


class TestComplianceRule:
    def test_compliance_rule_creation(self):
        rule = ComplianceRule(
            rule_id="S3-1",
            name="S3 Bucket Public Access",
            description="Test description",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS AWS",
            version="1.0.0",
            category="S3",
            remediation="Enable block public access",
            check_function="s3_public_access",
            cloud_provider=CloudProvider.AWS,
            tags=["storage", "public-access"],
        )

        assert rule.rule_id == "S3-1"
        assert rule.severity == SeverityLevel.CRITICAL
        assert len(rule.tags) == 2


class TestAWSComplianceChecker:
    def setup_method(self):
        self.checker = AWSComplianceChecker()

    def test_s3_public_access_compliant(self):
        resource = {
            "Name": "test-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        }

        rule = ComplianceRule(
            rule_id="S3-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="S3",
            remediation="Test",
            check_function="s3_public_access",
            cloud_provider=CloudProvider.AWS,
        )

        assert self.checker.check(resource, rule) is True

    def test_s3_public_access_non_compliant(self):
        resource = {
            "Name": "test-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        }

        rule = ComplianceRule(
            rule_id="S3-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="S3",
            remediation="Test",
            check_function="s3_public_access",
            cloud_provider=CloudProvider.AWS,
        )

        assert self.checker.check(resource, rule) is False

    def test_security_group_open_ssh(self):
        resource = {
            "ResourceType": "AWS::EC2::SecurityGroup",
            "IpPermissions": [
                {
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "FromPort": 22,
                    "ToPort": 22,
                }
            ],
        }

        rule = ComplianceRule(
            rule_id="EC2-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="EC2",
            remediation="Test",
            check_function="security_group_open",
            cloud_provider=CloudProvider.AWS,
        )

        assert self.checker.check(resource, rule) is False

    def test_security_group_restricted(self):
        resource = {
            "ResourceType": "AWS::EC2::SecurityGroup",
            "IpPermissions": [
                {
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "FromPort": 22,
                    "ToPort": 22,
                }
            ],
        }

        rule = ComplianceRule(
            rule_id="EC2-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="EC2",
            remediation="Test",
            check_function="security_group_open",
            cloud_provider=CloudProvider.AWS,
        )

        assert self.checker.check(resource, rule) is True

    def test_rds_public_access(self):
        resource = {
            "ResourceType": "AWS::RDS::DBInstance",
            "PubliclyAccessible": True,
        }

        rule = ComplianceRule(
            rule_id="RDS-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="RDS",
            remediation="Test",
            check_function="rds_public_access",
            cloud_provider=CloudProvider.AWS,
        )

        assert self.checker.check(resource, rule) is False

    def test_ebs_encrypted(self):
        resource = {
            "ResourceType": "AWS::EC2::Volume",
            "Encrypted": True,
        }

        rule = ComplianceRule(
            rule_id="EC2-2",
            name="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            benchmark="CIS",
            version="1.0",
            category="EC2",
            remediation="Test",
            check_function="ebs_encrypted",
            cloud_provider=CloudProvider.AWS,
        )

        assert self.checker.check(resource, rule) is True


class TestAzureComplianceChecker:
    def setup_method(self):
        self.checker = AzureComplianceChecker()

    def test_storage_https_only_compliant(self):
        resource = {
            "enableHttpsTrafficOnly": True,
        }

        rule = ComplianceRule(
            rule_id="AZURE-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            benchmark="CIS",
            version="1.0",
            category="Storage",
            remediation="Test",
            check_function="storage_https_only",
            cloud_provider=CloudProvider.AZURE,
        )

        assert self.checker.check(resource, rule) is True

    def test_nsg_open_to_internet(self):
        resource = {
            "securityRules": [
                {
                    "access": "Allow",
                    "destinationPortRange": "22",
                    "sourceAddressPrefix": "*",
                }
            ],
        }

        rule = ComplianceRule(
            rule_id="AZURE-2",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="Network",
            remediation="Test",
            check_function="network_security_group",
            cloud_provider=CloudProvider.AZURE,
        )

        assert self.checker.check(resource, rule) is False


class TestGCPComplianceChecker:
    def setup_method(self):
        self.checker = GCPComplianceChecker()

    def test_firewall_no_open_ssh(self):
        resource = {
            "rules": [
                {
                    "action": "allow",
                    "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                }
            ],
        }

        rule = ComplianceRule(
            rule_id="GCP-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="Network",
            remediation="Test",
            check_function="firewall_no_open",
            cloud_provider=CloudProvider.GCP,
        )

        assert self.checker.check(resource, rule) is False

    def test_bucket_uniform_access(self):
        resource = {
            "iamConfiguration": {
                "uniformBucketLevelAccess": {"enabled": True},
            },
        }

        rule = ComplianceRule(
            rule_id="GCP-2",
            name="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            benchmark="CIS",
            version="1.0",
            category="Storage",
            remediation="Test",
            check_function="bucket_no_public",
            cloud_provider=CloudProvider.GCP,
        )

        assert self.checker.check(resource, rule) is True


class TestKubernetesComplianceChecker:
    def setup_method(self):
        self.checker = KubernetesComplianceChecker()

    def test_no_privileged_container(self):
        resource = {
            "PodSpec": {
                "containers": [
                    {
                        "securityContext": {
                            "privileged": False,
                        }
                    }
                ]
            }
        }

        rule = ComplianceRule(
            rule_id="K8S-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="Pod Security",
            remediation="Test",
            check_function="no_privileged",
            cloud_provider=CloudProvider.KUBERNETES,
        )

        assert self.checker.check(resource, rule) is True

    def test_privileged_container(self):
        resource = {
            "PodSpec": {
                "containers": [
                    {
                        "securityContext": {
                            "privileged": True,
                        }
                    }
                ]
            }
        }

        rule = ComplianceRule(
            rule_id="K8S-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="Pod Security",
            remediation="Test",
            check_function="no_privileged",
            cloud_provider=CloudProvider.KUBERNETES,
        )

        assert self.checker.check(resource, rule) is False

    def test_read_only_root_fs(self):
        resource = {
            "PodSpec": {
                "containers": [
                    {
                        "securityContext": {
                            "readOnlyRootFilesystem": True,
                        }
                    }
                ]
            }
        }

        rule = ComplianceRule(
            rule_id="K8S-2",
            name="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            benchmark="CIS",
            version="1.0",
            category="Pod Security",
            remediation="Test",
            check_function="read_only_root_fs",
            cloud_provider=CloudProvider.KUBERNETES,
        )

        assert self.checker.check(resource, rule) is True


class TestTerraformComplianceChecker:
    def setup_method(self):
        self.checker = TerraformComplianceChecker()

    def test_s3_versioning_enabled(self):
        resource = {
            "versioning": {"enabled": True},
        }

        rule = ComplianceRule(
            rule_id="TF-1",
            name="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            benchmark="CIS",
            version="1.0",
            category="S3",
            remediation="Test",
            check_function="s3_enable_versioning",
            cloud_provider=CloudProvider.TERRAFORM,
        )

        assert self.checker.check(resource, rule) is True

    def test_no_hardcoded_secrets(self):
        resource = {
            "access_key": "AKIA1234567890ABCDEF",
        }

        rule = ComplianceRule(
            rule_id="TF-4",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="Security",
            remediation="Test",
            check_function="no_hardcoded_secrets",
            cloud_provider=CloudProvider.TERRAFORM,
        )

        assert self.checker.check(resource, rule) is False

    def test_no_hardcoded_secrets_clean(self):
        resource = {
            "access_key": "${var.aws_access_key}",
        }

        rule = ComplianceRule(
            rule_id="TF-4",
            name="Test",
            description="Test",
            severity=SeverityLevel.CRITICAL,
            benchmark="CIS",
            version="1.0",
            category="Security",
            remediation="Test",
            check_function="no_hardcoded_secrets",
            cloud_provider=CloudProvider.TERRAFORM,
        )

        assert self.checker.check(resource, rule) is True


class TestRuleEngine:
    def setup_method(self):
        self.engine = RuleEngine()

    def test_engine_loads_rules(self):
        assert len(self.engine.rules) > 0
        assert "S3-1" in self.engine.rules
        assert "IAM-1" in self.engine.rules
        assert "EC2-1" in self.engine.rules

    def test_get_rules_by_provider(self):
        aws_rules = self.engine.get_rules(cloud_provider=CloudProvider.AWS)
        assert len(aws_rules) > 0
        assert all(r.cloud_provider == CloudProvider.AWS for r in aws_rules)

    def test_get_rules_by_category(self):
        s3_rules = self.engine.get_rules(category="S3")
        assert len(s3_rules) > 0
        assert all(r.category == "S3" for r in s3_rules)

    def test_get_rules_by_severity(self):
        critical_rules = self.engine.get_rules(severity=SeverityLevel.CRITICAL)
        assert len(critical_rules) > 0
        assert all(r.severity == SeverityLevel.CRITICAL for r in critical_rules)

    def test_evaluate_resource_returns_findings(self):
        resource = {
            "Id": "sg-12345",
            "Name": "open-sg",
            "ResourceType": "AWS::EC2::SecurityGroup",
            "IpPermissions": [
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ],
        }

        findings = self.engine.evaluate_resource(
            resource,
            "AWS::EC2::SecurityGroup",
            CloudProvider.AWS,
        )

        assert len(findings) > 0
        assert any(f.rule_id == "EC2-1" for f in findings)

    def test_scan_resources_returns_result(self):
        resources = [
            {
                "Id": "sg-1",
                "Name": "sg-1",
                "ResourceType": "AWS::EC2::SecurityGroup",
                "IpPermissions": [],
            },
            {
                "Id": "sg-2",
                "Name": "sg-2",
                "ResourceType": "AWS::EC2::SecurityGroup",
                "IpPermissions": [
                    {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
            },
        ]

        result = self.engine.scan_resources(resources, CloudProvider.AWS)

        assert result.scan_id.startswith("scan-")
        assert result.cloud_provider == CloudProvider.AWS
        assert result.total_resources == 2
        assert result.summary["total_findings"] > 0
        assert result.duration_seconds >= 0


class TestScanResult:
    def test_scan_result_creation(self):
        findings = [
            Finding(
                finding_id="test-1",
                rule_id="S3-1",
                resource_id="bucket-1",
                resource_type="AWS::S3::Bucket",
                resource_name="bucket-1",
                status=ComplianceStatus.NON_COMPLIANT,
                severity=SeverityLevel.CRITICAL,
                message="Test violation",
                remediation="Fix it",
                evidence={},
                timestamp=datetime.utcnow(),
                cloud_provider=CloudProvider.AWS,
            )
        ]

        result = ScanResult(
            scan_id="scan-123",
            timestamp=datetime.utcnow(),
            cloud_provider=CloudProvider.AWS,
            total_resources=10,
            scanned_resources=10,
            findings=findings,
            summary={
                "total_findings": 1,
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "compliant": 9,
            },
            duration_seconds=5.5,
            rules_applied=["S3-1", "IAM-1"],
        )

        assert result.scan_id == "scan-123"
        assert len(result.findings) == 1
        assert result.summary["compliant"] == 9

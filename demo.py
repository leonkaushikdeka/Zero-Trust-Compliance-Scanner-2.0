#!/usr/bin/env python3
"""
Zero-Trust Compliance Scanner - Complete Demonstration
=====================================================
This script demonstrates all features of the compliance scanner.
"""

import sys
import os
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))


def print_header(title):
    """Print a formatted header."""
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)
    print()


def print_section(title):
    """Print a formatted section header."""
    print()
    print(f"--- {title} ---")
    print()


def demo_core_components():
    """Demonstrate core configuration and rule engine."""
    print_header("CORE COMPONENTS DEMONSTRATION")

    print_section("1. Configuration Classes")

    from core.config import (
        ScannerConfig,
        CloudProvider,
        SeverityLevel,
        ComplianceStatus,
        ComplianceRule,
        Finding,
        ScanResult,
    )

    # Default config
    config = ScannerConfig()
    print(f"Default config - Providers: {config.enabled_providers}")
    print(f"Default config - Regions: {config.aws_regions}")
    print(f"Default config - Severity threshold: {config.severity_threshold}")

    # Custom config
    custom_config = ScannerConfig(
        enabled_providers=[CloudProvider.AWS, CloudProvider.AZURE],
        aws_regions=["us-east-1", "us-west-2"],
        severity_threshold=SeverityLevel.HIGH,
        batch_size=50,
        dry_run=True,
    )
    print(
        f"Custom config - Providers: {[p.value for p in custom_config.enabled_providers]}"
    )
    print(f"Custom config - Severity: {custom_config.severity_threshold.value}")

    print_section("2. Rule Engine")

    from core.rule_engine import RuleEngine

    engine = RuleEngine()
    print(f"Total rules loaded: {len(engine.rules)}")
    print()

    # Count rules by provider
    rules_by_provider = {}
    for rule_id, rule in engine.rules.items():
        provider = rule.cloud_provider.value
        rules_by_provider[provider] = rules_by_provider.get(provider, 0) + 1

    print("Rules by provider:")
    for provider, count in sorted(rules_by_provider.items()):
        print(f"  {provider}: {count} rules")
    print()

    # Count rules by severity
    rules_by_severity = {}
    for rule_id, rule in engine.rules.items():
        severity = rule.severity.value
        rules_by_severity[severity] = rules_by_severity.get(severity, 0) + 1

    print("Rules by severity:")
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = rules_by_severity.get(severity, 0)
        print(f"  {severity}: {count} rules")


def demo_aws_checks():
    """Demonstrate AWS compliance checks."""
    print_header("AWS COMPLIANCE CHECK DEMONSTRATION")

    from core.config import CloudProvider, SeverityLevel
    from core.rule_engine import AWSComplianceChecker, RuleEngine

    engine = RuleEngine()
    checker = AWSComplianceChecker()

    print_section("1. S3 Bucket Public Access (CIS S3-1)")

    # Compliant bucket
    compliant_bucket = {
        "Name": "secure-bucket",
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }

    rule = engine.rules["S3-1"]
    result = checker.check(compliant_bucket, rule)
    print(f"Compliant bucket: {'PASS' if result else 'FAIL'}")
    print(f"  Rule: {rule.name}")
    print(f"  Severity: {rule.severity.value}")

    # Non-compliant bucket
    non_compliant_bucket = {
        **compliant_bucket,
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }
    result = checker.check(non_compliant_bucket, rule)
    print(f"Non-compliant bucket: {'FAIL' if not result else 'PASS'}")

    print_section("2. Security Group Open SSH (CIS EC2-1)")

    # Open SSH
    open_sg = {
        "ResourceType": "AWS::EC2::SecurityGroup",
        "IpPermissions": [
            {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22}
        ],
    }

    rule = engine.rules["EC2-1"]
    result = checker.check(open_sg, rule)
    print(f"Open SSH (0.0.0.0/0): {'NON-COMPLIANT' if not result else 'COMPLIANT'}")

    # Restricted SSH
    restricted_sg = {
        **open_sg,
        "IpPermissions": [
            {"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "FromPort": 22, "ToPort": 22}
        ],
    }
    result = checker.check(restricted_sg, rule)
    print(f"Restricted SSH (10.0.0.0/8): {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    print_section("3. RDS Public Access (CIS RDS-1)")

    public_rds = {
        "ResourceType": "AWS::RDS::DBInstance",
        "PubliclyAccessible": True,
    }

    rule = engine.rules["RDS-1"]
    result = checker.check(public_rds, rule)
    print(f"Public RDS: {'NON-COMPLIANT' if not result else 'COMPLIANT'}")

    private_rds = {**public_rds, "PubliclyAccessible": False}
    result = checker.check(private_rds, rule)
    print(f"Private RDS: {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    print_section("4. EBS Encryption (CIS EC2-2)")

    encrypted_ebs = {
        "ResourceType": "AWS::EC2::Volume",
        "Encrypted": True,
    }

    rule = engine.rules["EC2-2"]
    result = checker.check(encrypted_ebs, rule)
    print(f"Encrypted EBS: {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    unencrypted_ebs = {**encrypted_ebs, "Encrypted": False}
    result = checker.check(unencrypted_ebs, rule)
    print(f"Unencrypted EBS: {'NON-COMPLIANT' if not result else 'COMPLIANT'}")

    print_section("5. IAM Password Policy (CIS IAM-1)")

    strict_password_policy = {
        "PasswordPolicy": {
            "MinimumLength": 14,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        }
    }

    rule = engine.rules["IAM-1"]
    result = checker.check(strict_password_policy, rule)
    print(f"Strict password policy: {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    weak_password_policy = {
        **strict_password_policy,
        "MinimumLength": 8,
        "RequireSymbols": False,
    }
    result = checker.check(weak_password_policy, rule)
    print(f"Weak password policy: {'NON-COMPLIANT' if not result else 'COMPLIANT'}")


def demo_multi_cloud_checks():
    """Demonstrate multi-cloud compliance checks."""
    print_header("MULTI-CLOUD COMPLIANCE CHECK DEMONSTRATION")

    from core.config import CloudProvider
    from core.rule_engine import (
        AzureComplianceChecker,
        GCPComplianceChecker,
        KubernetesComplianceChecker,
        TerraformComplianceChecker,
    )

    print_section("1. Azure Storage HTTPS (CIS AZURE-1)")

    azure_checker = AzureComplianceChecker()

    compliant_storage = {"enableHttpsTrafficOnly": True}
    rule = {"check_function": "storage_https_only"}
    result = azure_checker.check(compliant_storage, type("R", (), rule)())
    print(f"Azure HTTPS only: {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    non_compliant_storage = {"enableHttpsTrafficOnly": False}
    result = azure_checker.check(non_compliant_storage, type("R", (), rule)())
    print(f"Azure HTTP allowed: {'NON-COMPLIANT' if not result else 'COMPLIANT'}")

    print_section("2. GCP Firewall (CIS GCP-1)")

    gcp_checker = GCPComplianceChecker()

    restricted_firewall = {
        "rules": [
            {
                "action": "allow",
                "sourceRanges": ["10.0.0.0/8"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            }
        ],
    }
    rule = {"check_function": "firewall_no_open"}
    result = gcp_checker.check(restricted_firewall, type("R", (), rule)())
    print(f"GCP restricted firewall: {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    open_firewall = {
        "rules": [
            {
                "action": "allow",
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            }
        ],
    }
    result = gcp_checker.check(open_firewall, type("R", (), rule)())
    print(f"GCP open firewall: {'NON-COMPLIANT' if not result else 'COMPLIANT'}")

    print_section("3. Kubernetes Pod Security (CIS K8S-1)")

    k8s_checker = KubernetesComplianceChecker()

    secure_pod = {
        "PodSpec": {
            "containers": [
                {
                    "securityContext": {
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                    }
                }
            ]
        }
    }
    rule = {"check_function": "no_privileged"}
    result = k8s_checker.check(secure_pod, type("R", (), rule)())
    print(f"K8s non-privileged: {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    privileged_pod = {
        "PodSpec": {"containers": [{"securityContext": {"privileged": True}}]}
    }
    result = k8s_checker.check(privileged_pod, type("R", (), rule)())
    print(f"K8s privileged container: {'NON-COMPLIANT' if not result else 'COMPLIANT'}")

    print_section("4. Terraform Secrets (CIS TF-4)")

    tf_checker = TerraformComplianceChecker()

    clean_tf = {"access_key": "${var.aws_access_key}"}
    rule = {"check_function": "no_hardcoded_secrets"}
    result = tf_checker.check(clean_tf, type("R", (), rule)())
    print(f"Terraform variable ref: {'COMPLIANT' if result else 'NON-COMPLIANT'}")

    secret_tf = {"access_key": "AKIA1234567890ABCDEF"}
    result = tf_checker.check(secret_tf, type("R", (), rule)())
    print(
        f"Terraform hardcoded secret: {'NON-COMPLIANT' if not result else 'COMPLIANT'}"
    )


def demo_full_scan():
    """Demonstrate a full compliance scan."""
    print_header("FULL COMPLIANCE SCAN DEMONSTRATION")

    from core.config import CloudProvider
    from core.rule_engine import RuleEngine

    engine = RuleEngine()

    # Create test resources
    test_resources = [
        # AWS Resources
        {
            "Id": "sg-open-ssh",
            "Name": "open-ssh-sg",
            "ResourceType": "AWS::EC2::SecurityGroup",
            "IpPermissions": [
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22}
            ],
            "Region": "us-east-1",
        },
        {
            "Id": "sg-closed",
            "Name": "closed-sg",
            "ResourceType": "AWS::EC2::SecurityGroup",
            "IpPermissions": [],
            "Region": "us-east-1",
        },
        {
            "Id": "bucket-public",
            "Name": "public-bucket",
            "ResourceType": "AWS::S3::Bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "Region": "us-east-1",
        },
        {
            "Id": "bucket-private",
            "Name": "private-bucket",
            "ResourceType": "AWS::S3::Bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "Region": "us-east-1",
        },
        {
            "Id": "rds-public",
            "Name": "public-db",
            "ResourceType": "AWS::RDS::DBInstance",
            "PubliclyAccessible": True,
            "Region": "us-east-1",
        },
        {
            "Id": "ebs-unencrypted",
            "Name": "unencrypted-volume",
            "ResourceType": "AWS::EC2::Volume",
            "Encrypted": False,
            "Region": "us-east-1",
        },
        {
            "Id": "ebs-encrypted",
            "Name": "encrypted-volume",
            "ResourceType": "AWS::EC2::Volume",
            "Encrypted": True,
            "Region": "us-east-1",
        },
    ]

    print_section("Scan Results")
    print(f"Total resources scanned: {len(test_resources)}")

    result = engine.scan_resources(test_resources, CloudProvider.AWS)

    print()
    print("Summary:")
    print(f"  Compliant resources: {result.summary['compliant']}")
    print(f"  Total findings: {result.summary['total_findings']}")
    print(f"  By severity:")
    print(f"    Critical: {result.summary.get('critical', 0)}")
    print(f"    High: {result.summary.get('high', 0)}")
    print(f"    Medium: {result.summary.get('medium', 0)}")
    print(f"    Low: {result.summary.get('low', 0)}")

    # Calculate compliance score
    if result.total_resources > 0:
        score = (result.summary["compliant"] / result.total_resources) * 100
        print()
        print(f"Compliance Score: {score:.1f}%")

    print()
    print("Findings:")
    for finding in result.findings:
        print(
            f"  [{finding.severity.value.upper()}] {finding.rule_id}: {finding.resource_id}"
        )
        print(f"    {finding.message}")
        print(f"    Remediation: {finding.remediation[:80]}...")

    print()
    print(f"Scan ID: {result.scan_id}")
    print(f"Duration: {result.duration_seconds:.3f}s")
    print(f"Rules applied: {len(result.rules_applied)}")


def demo_ci_cd_integration():
    """Demonstrate CI/CD integration."""
    print_header("CI/CD INTEGRATION DEMONSTRATION")

    from integrations.cicd_integration import (
        GitHubActionsIntegrator,
        ComplianceGateValidator,
        ScanConfig,
        CICDPlatform,
        create_cicd_pipeline,
    )

    print_section("1. GitHub Actions Workflow")

    gh_integrator = GitHubActionsIntegrator()
    scan_config = ScanConfig(
        provider="aws",
        commit_sha="abc123def456",
        branch="main",
        repository="acmeCorp/infrastructure",
        pipeline_id="workflow-12345",
        threshold_score=80,
    )

    workflow = gh_integrator.generate_workflow(scan_config)
    print(f"Generated workflow ({len(workflow)} chars)")
    print()
    print("Workflow excerpt:")
    print("-" * 40)
    lines = workflow.split("\n")
    for line in lines[:15]:
        print(line)
    print("...")

    print_section("2. Compliance Gate Validation")

    validator = ComplianceGateValidator()

    # Passing validation
    passing_report = {
        "compliance_score": 92,
        "findings": [],
        "findings_summary": {
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 2,
        },
    }

    validation = validator.validate_result(passing_report)
    print(f"Passing validation: {validation['passed']}")
    print(f"  Score: {validation['score']}%")
    print(f"  Violations: {len(validation['violations'])}")

    # Failing validation
    failing_report = {
        "compliance_score": 65,
        "findings": [
            {"severity": "critical", "rule_id": "S3-1"},
            {"severity": "high", "rule_id": "EC2-1"},
        ],
        "findings_summary": {
            "critical": 1,
            "high": 1,
            "medium": 3,
            "low": 5,
        },
    }

    validation = validator.validate_result(failing_report)
    print()
    print(f"Failing validation: {validation['passed']}")
    print(f"  Score: {validation['score']}%")
    print(f"  Violations: {len(validation['violations'])}")
    for violation in validation["violations"]:
        print(f"    - {violation['type']}: {violation['message']}")

    print_section("3. Multi-Platform Support")

    platforms = [
        (CICDPlatform.GITHUB_ACTIONS, "GitHub Actions"),
        (CICDPlatform.GITLAB_CI, "GitLab CI"),
        (CICDPlatform.AZURE_DEVOPS, "Azure DevOps"),
    ]

    print("Supported CI/CD platforms:")
    for platform, name in platforms:
        print(f"  - {name}")


def demo_reporting():
    """Demonstrate reporting functionality."""
    print_header("REPORTING DEMONSTRATION")

    from core.config import ScannerConfig, CloudProvider
    from core.rule_engine import RuleEngine

    engine = RuleEngine()

    # Run a scan
    test_resources = [
        {
            "Id": "sg-1",
            "Name": "open-sg",
            "ResourceType": "AWS::EC2::SecurityGroup",
            "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        },
        {
            "Id": "sg-2",
            "Name": "closed-sg",
            "ResourceType": "AWS::EC2::SecurityGroup",
            "IpPermissions": [],
        },
        {
            "Id": "bucket-1",
            "Name": "public-bucket",
            "ResourceType": "AWS::S3::Bucket",
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": False},
        },
    ]

    result = engine.scan_resources(test_resources, CloudProvider.AWS)

    print_section("JSON Report")
    report = {
        "scan_id": result.scan_id,
        "timestamp": result.timestamp.isoformat(),
        "provider": result.cloud_provider.value,
        "summary": result.summary,
        "compliance_score": round(
            (result.summary["compliant"] / result.total_resources) * 100, 2
        ),
        "pass": result.summary["critical"] == 0 and result.summary["high"] == 0,
        "findings_count": len(result.findings),
        "rules_applied": result.rules_applied,
    }

    print(json.dumps(report, indent=2, default=str))

    print_section("Summary Statistics")
    print(f"Total scans: 1")
    print(f"Resources scanned: {result.total_resources}")
    print(f"Findings: {result.summary['total_findings']}")
    print(
        f"Compliance rate: {(result.summary['compliant'] / result.total_resources) * 100:.1f}%"
    )


def main():
    """Run all demonstrations."""
    print()
    print("+" + "=" * 68 + "+")
    print("|" + " " * 10 + "ZERO-TRUST COMPLIANCE SCANNER" + " " * 26 + "|")
    print("|" + " " * 68 + "|")
    print("|  CIS Benchmark Compliance Scanner for Multi-Cloud" + " " * 21 + "|")
    print("|" + " " * 68 + "|")
    print("+" + "=" * 68 + "+")
    print()
    print(
        f"Demonstration executed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )

    # Run all demonstrations
    demo_core_components()
    demo_aws_checks()
    demo_multi_cloud_checks()
    demo_full_scan()
    demo_ci_cd_integration()
    demo_reporting()

    print_header("DEMONSTRATION COMPLETE")
    print("All Zero-Trust Compliance Scanner features have been demonstrated.")
    print()
    print("Next steps:")
    print("  1. Install dependencies: pip install -r requirements.txt")
    print("  2. Deploy to AWS: cd deploy/terraform && terraform apply")
    print("  3. Run in CI/CD: Add to your pipeline")
    print("  4. Customize rules: Edit src/core/rule_engine.py")
    print()
    print("For more information, see README.md")
    print()


if __name__ == "__main__":
    main()

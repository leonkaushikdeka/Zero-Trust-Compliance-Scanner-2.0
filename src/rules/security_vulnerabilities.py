"""
Security Vulnerability Rules Extension for Zero-Trust Compliance Scanner.

Additional security checks beyond CIS benchmarks for enterprise security posture.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from .config import CloudProvider, ComplianceRule, SeverityLevel

logger = logging.getLogger(__name__)


class SecurityVulnerabilityRules:
    """Extended security vulnerability rules beyond CIS benchmarks."""

    def __init__(self):
        self.rules = self._load_security_rules()

    def _load_security_rules(self) -> Dict[str, ComplianceRule]:
        """Load security vulnerability rules."""
        return {
            # AWS Security Rules
            "SEC-AWS-001": ComplianceRule(
                rule_id="SEC-AWS-001",
                name="EC2 Instance Has Public IP",
                description="EC2 instances with public IP addresses should be reviewed for security exposure",
                severity=SeverityLevel.MEDIUM,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Network",
                remediation="Remove public IP or place instance in private subnet with NAT gateway",
                check_function="check_ec2_public_ip",
                cloud_provider=CloudProvider.AWS,
                tags=["ec2", "network", "exposure"],
            ),
            "SEC-AWS-002": ComplianceRule(
                rule_id="SEC-AWS-002",
                name="IAM User Has Access Keys",
                description="IAM users with access keys should rotate them regularly",
                severity=SeverityLevel.HIGH,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Identity",
                remediation="Remove access keys and use IAM roles instead. If required, rotate keys every 90 days",
                check_function="check_iam_access_keys",
                cloud_provider=CloudProvider.AWS,
                tags=["iam", "access-keys", "rotation"],
            ),
            "SEC-AWS-003": ComplianceRule(
                rule_id="SEC-AWS-003",
                name="S3 Bucket Has ACL Configured",
                description="S3 buckets using ACLs should be reviewed for proper access control",
                severity=SeverityLevel.MEDIUM,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Storage",
                remediation="Use IAM policies instead of ACLs for access control",
                check_function="check_s3_acl",
                cloud_provider=CloudProvider.AWS,
                tags=["s3", "acl", "iam"],
            ),
            "SEC-AWS-004": ComplianceRule(
                rule_id="SEC-AWS-004",
                name="VPC Flow Logs Disabled",
                description="VPC flow logs should be enabled for network traffic analysis",
                severity=SeverityLevel.MEDIUM,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Network",
                remediation="Enable VPC flow logs for all VPCs",
                check_function="check_vpc_flow_logs",
                cloud_provider=CloudProvider.AWS,
                tags=["vpc", "flow-logs", "monitoring"],
            ),
            "SEC-AWS-005": ComplianceRule(
                rule_id="SEC-AWS-005",
                name="Lambda Function Uses Runtime Nodejs14.x",
                description="Lambda functions should use current Node.js runtime version",
                severity=SeverityLevel.LOW,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Compute",
                remediation="Update Lambda function to use Node.js 18.x or later",
                check_function="check_lambda_runtime",
                cloud_provider=CloudProvider.AWS,
                tags=["lambda", "runtime", "updates"],
            ),
            # General Security Rules
            "SEC-GEN-001": ComplianceRule(
                rule_id="SEC-GEN-001",
                name="Hardcoded IP Address in Configuration",
                description="Hardcoded IP addresses reduce infrastructure flexibility and security",
                severity=SeverityLevel.MEDIUM,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Configuration",
                remediation="Use DNS names or security group references instead of IP addresses",
                check_function="check_hardcoded_ip",
                cloud_provider=CloudProvider.TERRAFORM,
                tags=["configuration", "ip-address", "flexibility"],
            ),
            "SEC-GEN-002": ComplianceRule(
                rule_id="SEC-GEN-002",
                name="Default Port Numbers in Configuration",
                description="Using default port numbers is a security risk",
                severity=SeverityLevel.LOW,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Configuration",
                remediation="Use non-default port numbers for services",
                check_function="check_default_ports",
                cloud_provider=CloudProvider.TERRAFORM,
                tags=["configuration", "ports", "security"],
            ),
            "SEC-GEN-003": ComplianceRule(
                rule_id="SEC-GEN-003",
                name="Resource Without Tags",
                description="Resources should be tagged for cost allocation and security tracking",
                severity=SeverityLevel.INFO,
                benchmark="Security Best Practices",
                version="1.0.0",
                category="Governance",
                remediation="Add appropriate tags to resources",
                check_function="check_resource_tags",
                cloud_provider=CloudProvider.AWS,
                tags=["tags", "governance", "cost"],
            ),
        }

    def get_rules(self) -> List[ComplianceRule]:
        """Get all security vulnerability rules."""
        return list(self.rules.values())

    def get_rules_by_severity(self, severity: SeverityLevel) -> List[ComplianceRule]:
        """Get rules by severity level."""
        return [rule for rule in self.rules.values() if rule.severity == severity]


class SecurityVulnerabilityChecker:
    """Checker for security vulnerability rules."""

    def __init__(self):
        self.rules_loader = SecurityVulnerabilityRules()

    def check_ec2_public_ip(
        self, resource: Dict[str, Any], rule: ComplianceRule
    ) -> bool:
        """Check if EC2 instance has public IP."""
        public_ip = resource.get("PublicIpAddress")
        # Having public IP is only a finding if it's explicitly exposed
        return public_ip is None or public_ip == ""

    def check_iam_access_keys(
        self, resource: Dict[str, Any], rule: ComplianceRule
    ) -> bool:
        """Check if IAM user has access keys."""
        # Check if access keys are present
        access_keys = resource.get("AccessKeys", [])
        if access_keys:
            # Check age of keys
            for key in access_keys:
                create_date = key.get("CreateDate", "")
                if create_date:
                    # Keys older than 90 days should be rotated
                    # This is a simplified check
                    return False
        return True

    def check_s3_acl(self, resource: Dict[str, Any], rule: ComplianceRule) -> bool:
        """Check if S3 bucket has ACL configured."""
        # If bucket uses ACLs instead of IAM policies
        acl = resource.get("ACL", "")
        if acl and acl not in ["private"]:
            return False
        return True

    def check_vpc_flow_logs(
        self, resource: Dict[str, Any], rule: ComplianceRule
    ) -> bool:
        """Check if VPC has flow logs enabled."""
        flow_logs = resource.get("FlowLogs", [])
        return len(flow_logs) > 0

    def check_lambda_runtime(
        self, resource: Dict[str, Any], rule: ComplianceRule
    ) -> bool:
        """Check Lambda function runtime version."""
        runtime = resource.get("Runtime", "")
        deprecated_runtimes = ["nodejs14.x", "nodejs12.x", "python3.7", "python3.8"]
        return runtime not in deprecated_runtimes

    def check_hardcoded_ip(
        self, resource: Dict[str, Any], rule: ComplianceRule
    ) -> bool:
        """Check for hardcoded IP addresses."""
        resource_str = json.dumps(resource)
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        # Exclude private IP ranges
        private_ips = [
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.2",
            "172.30.",
            "172.31.",
            "192.168.",
        ]
        matches = re.findall(ip_pattern, resource_str)
        for match in matches:
            if not any(match.startswith(pi) for pi in private_ips):
                return False
        return True

    def check_default_ports(
        self, resource: Dict[str, Any], rule: ComplianceRule
    ) -> bool:
        """Check for default port numbers."""
        resource_str = json.dumps(resource)
        default_ports = [":22", ":80", ":443", ":8080", ":3306"]
        for port in default_ports:
            if port in resource_str:
                return False
        return True

    def check_resource_tags(
        self, resource: Dict[str, Any], rule: ComplianceRule
    ) -> bool:
        """Check if resource has required tags."""
        tags = resource.get("Tags", [])
        required_tags = ["Environment", "Owner", "Project"]
        tag_keys = [t.get("Key", "") for t in tags]
        return all(tag in tag_keys for tag in required_tags)

    def evaluate(
        self, resource: Dict[str, Any], provider: CloudProvider
    ) -> List[Dict[str, Any]]:
        """Evaluate a resource against security vulnerability rules."""
        findings = []
        rules = self.rules_loader.get_rules()
        provider_rules = [
            r
            for r in rules
            if r.cloud_provider == provider
            or r.cloud_provider == CloudProvider.TERRAFORM
        ]

        for rule in provider_rules:
            checker_func = getattr(self, rule.check_function, None)
            if checker_func:
                try:
                    is_compliant = checker_func(resource, rule)
                    if not is_compliant:
                        findings.append(
                            {
                                "rule_id": rule.rule_id,
                                "name": rule.name,
                                "severity": rule.severity.value,
                                "message": rule.description,
                                "remediation": rule.remediation,
                            }
                        )
                except Exception as e:
                    logger.warning(f"Error checking rule {rule.rule_id}: {e}")

        return findings

import re
import hashlib
import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum
from datetime import datetime
import logging

from .config import (
    ComplianceRule,
    Finding,
    ComplianceStatus,
    SeverityLevel,
    CloudProvider,
    ScanResult,
)

logger = logging.getLogger(__name__)


class RuleValidator:
    @staticmethod
    def is_valid_rule_id(rule_id: str) -> bool:
        pattern = re.compile(r"^[A-Z]{2,4}-\d{3,4}$")
        return bool(pattern.match(rule_id))

    @staticmethod
    def validate_severity(severity: str) -> bool:
        return severity in [s.value for s in SeverityLevel]

    @staticmethod
    def validate_cloud_provider(provider: str) -> bool:
        return provider in [p.value for p in CloudProvider]


class ComplianceChecker(ABC):
    @abstractmethod
    def check(self, resource: Dict[str, Any], rule: ComplianceRule) -> bool:
        pass


class AWSComplianceChecker(ComplianceChecker):
    def __init__(self):
        self.check_registry: Dict[str, Callable] = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.check_registry["s3_public_access"] = self._check_s3_public_access
        self.check_registry["iam_password_policy"] = self._check_iam_password_policy
        self.check_registry["mfa_enabled"] = self._check_mfa_enabled
        self.check_registry["encryption_enabled"] = self._check_encryption_enabled
        self.check_registry["security_group_open"] = self._check_security_group_open
        self.check_registry["log_retention"] = self._check_log_retention
        self.check_registry["public_ami"] = self._check_public_ami
        self.check_registry["ebs_encrypted"] = self._check_ebs_encrypted
        self.check_registry["rds_public_access"] = self._check_rds_public_access
        self.check_registry["iam_no_admin"] = self._check_iam_no_admin

    def _check_s3_public_access(self, resource: Dict, rule: ComplianceRule) -> bool:
        bucket_name = resource.get("Name", "")
        config = resource.get("PublicAccessBlockConfiguration", {})
        block_public_acls = config.get("BlockPublicAcls", True)
        ignore_public_acls = config.get("IgnorePublicAcls", True)
        block_public_policy = config.get("BlockPublicPolicy", True)
        restrict_public_buckets = config.get("RestrictPublicBuckets", True)
        return all(
            [
                block_public_acls,
                ignore_public_acls,
                block_public_policy,
                restrict_public_buckets,
            ]
        )

    def _check_iam_password_policy(self, resource: Dict, rule: ComplianceRule) -> bool:
        policy = resource.get("PasswordPolicy", {})
        min_length = policy.get("MinimumLength", 14)
        require_uppercase = policy.get("RequireUppercaseCharacters", True)
        require_lowercase = policy.get("RequireLowercaseCharacters", True)
        require_numbers = policy.get("RequireNumbers", True)
        require_symbols = policy.get("RequireSymbols", True)
        max_age = policy.get("MaxPasswordAge", 90)
        reuse_prevention = policy.get("PasswordReusePrevention", 24)

        return (
            min_length >= 14
            and require_uppercase
            and require_lowercase
            and require_numbers
            and require_symbols
            and max_age <= 90
            and reuse_prevention >= 24
        )

    def _check_mfa_enabled(self, resource: Dict, rule: ComplianceRule) -> bool:
        mfa_enabled = resource.get("MFADevice", {}).get("Enabled", False)
        if rule.rule_id == "IAM-1":
            return mfa_enabled
        return True

    def _check_encryption_enabled(self, resource: Dict, rule: ComplianceRule) -> bool:
        if "KMS" in resource.get("ResourceType", ""):
            key_usage = resource.get("KeyUsage", "ENCRYPT_DECRYPT")
            key_state = resource.get("KeyState", "Enabled")
            return key_usage == "ENCRYPT_DECRYPT" and key_state == "Enabled"
        return True

    def _check_security_group_open(self, resource: Dict, rule: ComplianceRule) -> bool:
        if resource.get("ResourceType") != "AWS::EC2::SecurityGroup":
            return True

        ip_permissions = resource.get("IpPermissions", [])
        for perm in ip_permissions:
            ip_ranges = perm.get("IpRanges", [])
            for ip_range in ip_ranges:
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    return False

        return True

    def _check_log_retention(self, resource: Dict, rule: ComplianceRule) -> bool:
        retention_days = resource.get("RetentionInDays", 365)
        required_days = int(rule.metadata.get("required_days", 365))
        return retention_days >= required_days

    def _check_public_ami(self, resource: Dict, rule: ComplianceRule) -> bool:
        image_type = resource.get("ImageType", "machine")
        public = resource.get("Public", False)
        return not public or image_type != "machine"

    def _check_ebs_encrypted(self, resource: Dict, rule: ComplianceRule) -> bool:
        ebs_encrypted = resource.get("Encrypted", True)
        return ebs_encrypted

    def _check_rds_public_access(self, resource: Dict, rule: ComplianceRule) -> bool:
        publicly_accessible = resource.get("PubliclyAccessible", False)
        return not publicly_accessible

    def _check_iam_no_admin(self, resource: Dict, rule: ComplianceRule) -> bool:
        assume_role_policy = resource.get("AssumeRolePolicyDocument", {})
        statements = assume_role_policy.get("Statement", [])
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal", {})
                if "*" in str(principal):
                    return False
        return True

    def check(self, resource: Dict, rule: ComplianceRule) -> bool:
        check_func = self.check_registry.get(rule.check_function)
        if check_func:
            return check_func(resource, rule)
        logger.warning(f"Unknown check function: {rule.check_function}")
        return True


class AzureComplianceChecker(ComplianceChecker):
    def __init__(self):
        self.check_registry: Dict[str, Callable] = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.check_registry["storage_https_only"] = self._check_storage_https_only
        self.check_registry["network_security_group"] = self._check_nsg_rules
        self.check_registry["blob_public_access"] = self._check_blob_public_access
        self.check_registry["defender_enabled"] = self._check_defender_enabled

    def _check_storage_https_only(self, resource: Dict, rule: ComplianceRule) -> bool:
        enable_https = resource.get("enableHttpsTrafficOnly", True)
        return enable_https

    def _check_nsg_rules(self, resource: Dict, rule: ComplianceRule) -> bool:
        security_rules = resource.get("securityRules", [])
        for rule_item in security_rules:
            if rule_item.get("access") == "Allow":
                destination_port_range = rule_item.get("destinationPortRange", "")
                if destination_port_range in ["*", "0-65535"]:
                    source_address_prefix = rule_item.get("sourceAddressPrefix", "")
                    if source_address_prefix in ["*", "0.0.0.0", "Internet"]:
                        return False
        return True

    def _check_blob_public_access(self, resource: Dict, rule: ComplianceRule) -> bool:
        allow_blob_public_access = resource.get("allowBlobPublicAccess", False)
        return not allow_blob_public_access

    def _check_defender_enabled(self, resource: Dict, rule: ComplianceRule) -> bool:
        pricing_tier = resource.get("pricingTier", "Standard")
        return pricing_tier == "Standard"

    def check(self, resource: Dict, rule: ComplianceRule) -> bool:
        check_func = self.check_registry.get(rule.check_function)
        if check_func:
            return check_func(resource, rule)
        return True


class GCPComplianceChecker(ComplianceChecker):
    def __init__(self):
        self.check_registry: Dict[str, Callable] = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.check_registry["firewall_no_open"] = self._check_firewall_rules
        self.check_registry["bucket_no_public"] = self._check_bucket_public_access
        self.check_registry["encryption_cmck"] = self._check_cmek_enabled
        self.check_registry["login_enabled"] = self._check_os_login

    def _check_firewall_rules(self, resource: Dict, rule: ComplianceRule) -> bool:
        rules = resource.get("rules", [])
        for rule_item in rules:
            if rule_item.get("action") == "allow":
                ranges = rule_item.get("sourceRanges", [])
                for cidr in ranges:
                    if cidr in ["0.0.0.0/0", "::/0"]:
                        ports = rule_item.get("allowed", [])
                        for port in ports:
                            if port.get("IPProtocol") in ["tcp", "udp", "all"]:
                                port_ranges = port.get("ports", [])
                                for pr in port_ranges:
                                    if pr in ["*", "0-65535"]:
                                        return False
        return True

    def _check_bucket_public_access(self, resource: Dict, rule: ComplianceRule) -> bool:
        iam_configuration = resource.get("iamConfiguration", {})
        uniform_bucket_level_access = iam_configuration.get(
            "uniformBucketLevelAccess", {"enabled": True}
        )
        is_uniform = uniform_bucket_level_access.get("enabled", True)
        return is_uniform

    def _check_cmek_enabled(self, resource: Dict, rule: ComplianceRule) -> bool:
        encryption_config = resource.get("encryptionConfig", {})
        default_kms_key = encryption_config.get("defaultKmsKeyName", "")
        return bool(default_kms_key)

    def _check_os_login(self, resource: Dict, rule: ComplianceRule) -> bool:
        metadata = resource.get("metadata", {})
        enable_oslogin = metadata.get("enable-oslogin", "TRUE")
        return enable_oslogin.upper() == "TRUE"

    def check(self, resource: Dict, rule: ComplianceRule) -> bool:
        check_func = self.check_registry.get(rule.check_function)
        if check_func:
            return check_func(resource, rule)
        return True


class KubernetesComplianceChecker(ComplianceChecker):
    def __init__(self):
        self.check_registry: Dict[str, Callable] = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.check_registry["pod_security_policy"] = self._check_psp
        self.check_registry["network_policy"] = self._check_network_policy
        self.check_registry["read_only_root_fs"] = self._check_readonly_rootfs
        self.check_registry["run_as_non_root"] = self._check_run_as_non_root
        self.check_registry["no_privileged"] = self._check_no_privileged
        self.check_registry["seccomp_profile"] = self._check_seccomp_profile

    def _check_psp(self, resource: Dict, rule: ComplianceRule) -> bool:
        psp = resource.get("PodSecurityPolicy", {})
        return bool(psp)

    def _check_network_policy(self, resource: Dict, rule: ComplianceRule) -> bool:
        policies = resource.get("NetworkPolicy", [])
        return len(policies) > 0

    def _check_readonly_rootfs(self, resource: Dict, rule: ComplianceRule) -> bool:
        pod_spec = resource.get("PodSpec", {})
        containers = pod_spec.get("containers", [])
        for container in containers:
            security_context = container.get("securityContext", {})
            read_only_root_fs = security_context.get("readOnlyRootFilesystem", False)
            if not read_only_root_fs:
                return False
        return True

    def _check_run_as_non_root(self, resource: Dict, rule: ComplianceRule) -> bool:
        pod_spec = resource.get("PodSpec", {})
        security_context = pod_spec.get("securityContext", {})
        run_as_non_root = security_context.get("runAsNonRoot", False)
        return run_as_non_root

    def _check_no_privileged(self, resource: Dict, rule: ComplianceRule) -> bool:
        pod_spec = resource.get("PodSpec", {})
        containers = pod_spec.get("containers", [])
        for container in containers:
            security_context = container.get("securityContext", {})
            privileged = security_context.get("privileged", False)
            if privileged:
                return False
        return True

    def _check_seccomp_profile(self, resource: Dict, rule: ComplianceRule) -> bool:
        pod_spec = resource.get("PodSpec", {})
        security_context = pod_spec.get("securityContext", {})
        seccomp_profile = security_context.get("seccompProfile", {})
        return bool(seccomp_profile.get("type"))

    def check(self, resource: Dict, rule: ComplianceRule) -> bool:
        check_func = self.check_registry.get(rule.check_function)
        if check_func:
            return check_func(resource, rule)
        return True


class TerraformComplianceChecker(ComplianceChecker):
    def __init__(self):
        self.check_registry: Dict[str, Callable] = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.check_registry["s3_enable_versioning"] = self._check_s3_versioning
        self.check_registry["s3_enable_logging"] = self._check_s3_logging
        self.check_registry["db_backup_enabled"] = self._check_db_backup
        self.check_registry["no_hardcoded_secrets"] = self._check_no_secrets
        self.check_registry["enable_mfa"] = self._check_mfa

    def _check_s3_versioning(self, resource: Dict, rule: ComplianceRule) -> bool:
        versioning = resource.get("versioning", {})
        enabled = versioning.get("enabled", True)
        return enabled

    def _check_s3_logging(self, resource: Dict, rule: ComplianceRule) -> bool:
        logging_config = resource.get("logging", {})
        target_bucket = logging_config.get("target_bucket", "")
        return bool(target_bucket)

    def _check_db_backup(self, resource: Dict, rule: ComplianceRule) -> bool:
        backup_retention_period = resource.get("backup_retention_period", 7)
        automated_backup = resource.get("auto_minor_version_upgrade", True)
        return backup_retention_period >= 7 and automated_backup

    def _check_no_secrets(self, resource: Dict, rule: ComplianceRule) -> bool:
        secret_patterns = [
            r"AKIA[0-9A-Z]{16}",
            r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*",
            r"-----BEGIN RSA PRIVATE KEY-----",
        ]
        resource_str = json.dumps(resource)
        for pattern in secret_patterns:
            if re.search(pattern, resource_str):
                return False
        return True

    def _check_mfa(self, resource: Dict, rule: ComplianceRule) -> bool:
        mfa_auth = resource.get("mfa_auth", True)
        return mfa_auth

    def check(self, resource: Dict, rule: ComplianceRule) -> bool:
        check_func = self.check_registry.get(rule.check_function)
        if check_func:
            return check_func(resource, rule)
        return True


class RuleEngine:
    def __init__(self):
        self.checkers: Dict[CloudProvider, ComplianceChecker] = {
            CloudProvider.AWS: AWSComplianceChecker(),
            CloudProvider.AZURE: AzureComplianceChecker(),
            CloudProvider.GCP: GCPComplianceChecker(),
            CloudProvider.KUBERNETES: KubernetesComplianceChecker(),
            CloudProvider.TERRAFORM: TerraformComplianceChecker(),
        }
        self.rules: Dict[str, ComplianceRule] = {}
        self._load_default_rules()

    def _load_default_rules(self):
        default_rules = self._get_aws_cis_benchmark_rules()
        default_rules.update(self._get_azure_cis_benchmark_rules())
        default_rules.update(self._get_gcp_cis_benchmark_rules())
        default_rules.update(self._get_k8s_cis_benchmark_rules())
        default_rules.update(self._get_terraform_cis_rules())
        self.rules = default_rules

    def _get_aws_cis_benchmark_rules(self) -> Dict[str, ComplianceRule]:
        return {
            "S3-1": ComplianceRule(
                rule_id="S3-1",
                name="S3 Bucket Public Access Restriction",
                description="S3 buckets should have all public access blocked at the account and bucket level",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="S3",
                remediation="Enable S3 Block Public Access configuration on the bucket and account level",
                check_function="s3_public_access",
                cloud_provider=CloudProvider.AWS,
                tags=["storage", "public-access", "data-protection"],
            ),
            "IAM-1": ComplianceRule(
                rule_id="IAM-1",
                name="IAM Password Policy",
                description="IAM password policy should require minimum length of 14 characters and various complexity requirements",
                severity=SeverityLevel.HIGH,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="IAM",
                remediation="Update IAM password policy to meet CIS requirements",
                check_function="iam_password_policy",
                cloud_provider=CloudProvider.AWS,
                tags=["iam", "authentication", "password"],
            ),
            "IAM-2": ComplianceRule(
                rule_id="IAM-2",
                name="MFA Enabled for IAM Users",
                description="All IAM users should have MFA enabled",
                severity=SeverityLevel.HIGH,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="IAM",
                remediation="Enable MFA for all IAM users",
                check_function="mfa_enabled",
                cloud_provider=CloudProvider.AWS,
                tags=["iam", "mfa", "authentication"],
            ),
            "EC2-1": ComplianceRule(
                rule_id="EC2-1",
                name="Security Groups - No Open SSH",
                description="Security groups should not allow unrestricted SSH access (port 22) from 0.0.0.0/0",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="EC2",
                remediation="Modify security group rules to restrict SSH access to specific IP ranges",
                check_function="security_group_open",
                cloud_provider=CloudProvider.AWS,
                tags=["ec2", "security-group", "network"],
            ),
            "EC2-2": ComplianceRule(
                rule_id="EC2-2",
                name="EBS Volume Encryption",
                description="EBS volumes should have encryption enabled",
                severity=SeverityLevel.HIGH,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="EC2",
                remediation="Enable encryption for EBS volumes",
                check_function="ebs_encrypted",
                cloud_provider=CloudProvider.AWS,
                tags=["ec2", "ebs", "encryption"],
            ),
            "RDS-1": ComplianceRule(
                rule_id="RDS-1",
                name="RDS Instance Public Access",
                description="RDS instances should not be publicly accessible",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="RDS",
                remediation="Modify RDS instance to disable public accessibility",
                check_function="rds_public_access",
                cloud_provider=CloudProvider.AWS,
                tags=["rds", "database", "public-access"],
            ),
            "KMS-1": ComplianceRule(
                rule_id="KMS-1",
                name="KMS Key Usage",
                description="KMS keys should be enabled for encryption/decryption",
                severity=SeverityLevel.MEDIUM,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="KMS",
                remediation="Configure KMS key for encryption/decryption usage",
                check_function="encryption_enabled",
                cloud_provider=CloudProvider.AWS,
                tags=["kms", "encryption"],
            ),
            "CWL-1": ComplianceRule(
                rule_id="CWL-1",
                name="CloudTrail Log Retention",
                description="CloudTrail logs should be retained for at least 365 days",
                severity=SeverityLevel.MEDIUM,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="CloudTrail",
                remediation="Update CloudTrail retention period to 365 days",
                check_function="log_retention",
                cloud_provider=CloudProvider.AWS,
                tags=["cloudtrail", "logging", "audit"],
                metadata={"required_days": 365},
            ),
            "IAM-3": ComplianceRule(
                rule_id="IAM-3",
                name="IAM No Admin Access",
                description="IAM roles should not allow wildcard principal in trust policies",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="IAM",
                remediation="Restrict IAM role trust policies to specific principals",
                check_function="iam_no_admin",
                cloud_provider=CloudProvider.AWS,
                tags=["iam", "privilege-escalation"],
            ),
            "EC2-3": ComplianceRule(
                rule_id="EC2-3",
                name="AMIs Not Public",
                description="AMIs should not be publicly shared",
                severity=SeverityLevel.HIGH,
                benchmark="CIS AWS Foundations Benchmark",
                version="1.2.0",
                category="EC2",
                remediation="Remove public sharing of AMIs",
                check_function="public_ami",
                cloud_provider=CloudProvider.AWS,
                tags=["ec2", "ami", "data-protection"],
            ),
        }

    def _get_azure_cis_benchmark_rules(self) -> Dict[str, ComplianceRule]:
        return {
            "AZURE-1": ComplianceRule(
                rule_id="AZURE-1",
                name="Storage Account HTTPS Only",
                description="Storage accounts should require HTTPS traffic only",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Microsoft Azure Foundations Benchmark",
                version="1.3.0",
                category="Storage",
                remediation="Enable 'Secure transfer required' on storage accounts",
                check_function="storage_https_only",
                cloud_provider=CloudProvider.AZURE,
                tags=["storage", "encryption", "transport"],
            ),
            "AZURE-2": ComplianceRule(
                rule_id="AZURE-2",
                name="Network Security Groups Restricted",
                description="NSG rules should not allow unrestricted access to management ports",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS Microsoft Azure Foundations Benchmark",
                version="1.3.0",
                category="Network",
                remediation="Modify NSG rules to restrict access to specific source IPs",
                check_function="network_security_group",
                cloud_provider=CloudProvider.AZURE,
                tags=["network", "nsg", "security"],
            ),
            "AZURE-3": ComplianceRule(
                rule_id="AZURE-3",
                name="Blob Storage Public Access Disabled",
                description="Blob storage should have public access disabled",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS Microsoft Azure Foundations Benchmark",
                version="1.3.0",
                category="Storage",
                remediation="Disable public blob access on storage accounts",
                check_function="blob_public_access",
                cloud_provider=CloudProvider.AZURE,
                tags=["storage", "blob", "public-access"],
            ),
            "AZURE-4": ComplianceRule(
                rule_id="AZURE-4",
                name="Microsoft Defender for Cloud Enabled",
                description="Microsoft Defender for Cloud should be enabled at Standard tier",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Microsoft Azure Foundations Benchmark",
                version="1.3.0",
                category="Security",
                remediation="Enable Microsoft Defender for Cloud with Standard pricing tier",
                check_function="defender_enabled",
                cloud_provider=CloudProvider.AZURE,
                tags=["security", "defender", "monitoring"],
            ),
        }

    def _get_gcp_cis_benchmark_rules(self) -> Dict[str, ComplianceRule]:
        return {
            "GCP-1": ComplianceRule(
                rule_id="GCP-1",
                name="Firewall No Open SSH/RDP",
                description="Firewall rules should not allow unrestricted SSH or RDP from 0.0.0.0/0",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS Google Cloud Platform Foundation Benchmark",
                version="1.0.0",
                category="Network",
                remediation="Modify firewall rules to restrict SSH/RDP access",
                check_function="firewall_no_open",
                cloud_provider=CloudProvider.GCP,
                tags=["gcp", "firewall", "network"],
            ),
            "GCP-2": ComplianceRule(
                rule_id="GCP-2",
                name="Storage Bucket Uniform Access",
                description="Storage buckets should use uniform bucket-level access",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Google Cloud Platform Foundation Benchmark",
                version="1.0.0",
                category="Storage",
                remediation="Enable uniform bucket-level access on storage buckets",
                check_function="bucket_no_public",
                cloud_provider=CloudProvider.GCP,
                tags=["gcp", "storage", "iam"],
            ),
            "GCP-3": ComplianceRule(
                rule_id="GCP-3",
                name="Storage Bucket CMEK Encryption",
                description="Storage buckets should use customer-managed encryption keys",
                severity=SeverityLevel.MEDIUM,
                benchmark="CIS Google Cloud Platform Foundation Benchmark",
                version="1.0.0",
                category="Storage",
                remediation="Configure CMEK for storage buckets",
                check_function="encryption_cmck",
                cloud_provider=CloudProvider.GCP,
                tags=["gcp", "storage", "encryption"],
            ),
            "GCP-4": ComplianceRule(
                rule_id="GCP-4",
                name="OS Login Enabled",
                description="Compute instances should have OS login enabled",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Google Cloud Platform Foundation Benchmark",
                version="1.0.0",
                category="Compute",
                remediation="Enable OS login on compute instances",
                check_function="login_enabled",
                cloud_provider=CloudProvider.GCP,
                tags=["gcp", "compute", "authentication"],
            ),
        }

    def _get_k8s_cis_benchmark_rules(self) -> Dict[str, ComplianceRule]:
        return {
            "K8S-1": ComplianceRule(
                rule_id="K8S-1",
                name="Pod Security Standards",
                description="Pods should not run with privileged container access",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS Kubernetes Benchmark",
                version="1.6.0",
                category="Pod Security",
                remediation="Remove privileged container settings from pod specifications",
                check_function="no_privileged",
                cloud_provider=CloudProvider.KUBERNETES,
                tags=["kubernetes", "pod", "privilege"],
            ),
            "K8S-2": ComplianceRule(
                rule_id="K8S-2",
                name="Read-Only Root Filesystem",
                description="Containers should use read-only root filesystem",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Kubernetes Benchmark",
                version="1.6.0",
                category="Pod Security",
                remediation="Set readOnlyRootFilesystem to true in container security context",
                check_function="read_only_root_fs",
                cloud_provider=CloudProvider.KUBERNETES,
                tags=["kubernetes", "pod", "filesystem"],
            ),
            "K8S-3": ComplianceRule(
                rule_id="K8S-3",
                name="Run As Non-Root",
                description="Pods should be configured to run as non-root user",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Kubernetes Benchmark",
                version="1.6.0",
                category="Pod Security",
                remediation="Configure runAsNonRoot in pod security context",
                check_function="run_as_non_root",
                cloud_provider=CloudProvider.KUBERNETES,
                tags=["kubernetes", "pod", "privilege"],
            ),
            "K8S-4": ComplianceRule(
                rule_id="K8S-4",
                name="Network Policy Defined",
                description="Namespaces should have network policies defined",
                severity=SeverityLevel.MEDIUM,
                benchmark="CIS Kubernetes Benchmark",
                version="1.6.0",
                category="Network",
                remediation="Create NetworkPolicy resources to restrict traffic",
                check_function="network_policy",
                cloud_provider=CloudProvider.KUBERNETES,
                tags=["kubernetes", "network", "policy"],
            ),
            "K8S-5": ComplianceRule(
                rule_id="K8S-5",
                name="Seccomp Profile Enabled",
                description="Pods should have seccomp profile configured",
                severity=SeverityLevel.MEDIUM,
                benchmark="CIS Kubernetes Benchmark",
                version="1.6.0",
                category="Pod Security",
                remediation="Configure seccomp profile in pod security context",
                check_function="seccomp_profile",
                cloud_provider=CloudProvider.KUBERNETES,
                tags=["kubernetes", "pod", "security"],
            ),
        }

    def _get_terraform_cis_rules(self) -> Dict[str, ComplianceRule]:
        return {
            "TF-1": ComplianceRule(
                rule_id="TF-1",
                name="S3 Bucket Versioning",
                description="S3 buckets should have versioning enabled",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Terraform Benchmark",
                version="1.0.0",
                category="S3",
                remediation="Enable versioning on S3 bucket resources",
                check_function="s3_enable_versioning",
                cloud_provider=CloudProvider.TERRAFORM,
                tags=["terraform", "s3", "versioning"],
            ),
            "TF-2": ComplianceRule(
                rule_id="TF-2",
                name="",
                description="S3 buckets shouldS3 Bucket Logging have server access logging enabled",
                severity=SeverityLevel.MEDIUM,
                benchmark="CIS Terraform Benchmark",
                version="1.0.0",
                category="S3",
                remediation="Enable logging on S3 bucket resources",
                check_function="s3_enable_logging",
                cloud_provider=CloudProvider.TERRAFORM,
                tags=["terraform", "s3", "logging"],
            ),
            "TF-3": ComplianceRule(
                rule_id="TF-3",
                name="Database Backup Configuration",
                description="Database resources should have appropriate backup configuration",
                severity=SeverityLevel.HIGH,
                benchmark="CIS Terraform Benchmark",
                version="1.0.0",
                category="Database",
                remediation="Configure backup_retention_period and auto_minor_version_upgrade",
                check_function="db_backup_enabled",
                cloud_provider=CloudProvider.TERRAFORM,
                tags=["terraform", "database", "backup"],
            ),
            "TF-4": ComplianceRule(
                rule_id="TF-4",
                name="No Hardcoded Secrets",
                description="Terraform configurations should not contain hardcoded secrets",
                severity=SeverityLevel.CRITICAL,
                benchmark="CIS Terraform Benchmark",
                version="1.0.0",
                category="Security",
                remediation="Remove hardcoded secrets and use environment variables or secrets manager",
                check_function="no_hardcoded_secrets",
                cloud_provider=CloudProvider.TERRAFORM,
                tags=["terraform", "secrets", "security"],
            ),
        }

    def register_rule(self, rule: ComplianceRule):
        if not RuleValidator.is_valid_rule_id(rule.rule_id):
            raise ValueError(f"Invalid rule ID: {rule.rule_id}")
        self.rules[rule.rule_id] = rule

    def get_rules(
        self,
        cloud_provider: Optional[CloudProvider] = None,
        category: Optional[str] = None,
        severity: Optional[SeverityLevel] = None,
    ) -> List[ComplianceRule]:
        rules = list(self.rules.values())

        if cloud_provider:
            rules = [r for r in rules if r.cloud_provider == cloud_provider]
        if category:
            rules = [r for r in rules if r.category == category]
        if severity:
            rules = [r for r in rules if r.severity == severity]

        return rules

    def evaluate_resource(
        self,
        resource: Dict[str, Any],
        resource_type: str,
        provider: CloudProvider,
        rule_ids: Optional[List[str]] = None,
    ) -> List[Finding]:
        findings = []

        if rule_ids is None:
            applicable_rules = [
                r for r in self.rules.values() if r.cloud_provider == provider
            ]
        else:
            applicable_rules = [
                r
                for r in self.rules.values()
                if r.rule_id in rule_ids and r.cloud_provider == provider
            ]

        checker = self.checkers.get(provider)
        if not checker:
            logger.warning(f"No checker available for provider: {provider}")
            return findings

        resource_name = resource.get(
            "Name", resource.get("name", resource.get("id", "unknown"))
        )
        resource_id = resource.get("Id", resource.get("id", resource_name))

        for rule in applicable_rules:
            try:
                is_compliant = checker.check(resource, rule)

                if not is_compliant:
                    finding = Finding(
                        finding_id=self._generate_finding_id(resource_id, rule.rule_id),
                        rule_id=rule.rule_id,
                        resource_id=resource_id,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        status=ComplianceStatus.NON_COMPLIANT,
                        severity=rule.severity,
                        message=f"Resource violates CIS benchmark rule: {rule.name}",
                        remediation=rule.remediation,
                        evidence={"resource": resource, "rule": rule.__dict__},
                        timestamp=datetime.utcnow(),
                        cloud_provider=provider,
                        region=resource.get("Region"),
                        account_id=resource.get("AccountId"),
                        metadata={"tags": rule.tags},
                    )
                    findings.append(finding)
            except Exception as e:
                logger.error(
                    f"Error evaluating rule {rule.rule_id} on resource {resource_id}: {e}"
                )
                finding = Finding(
                    finding_id=self._generate_finding_id(resource_id, rule.rule_id),
                    rule_id=rule.rule_id,
                    resource_id=resource_id,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    status=ComplianceStatus.ERROR,
                    severity=SeverityLevel.LOW,
                    message=f"Error evaluating rule: {str(e)}",
                    remediation=rule.remediation,
                    evidence={"error": str(e)},
                    timestamp=datetime.utcnow(),
                    cloud_provider=provider,
                )
                findings.append(finding)

        return findings

    def _generate_finding_id(self, resource_id: str, rule_id: str) -> str:
        unique_str = f"{resource_id}-{rule_id}-{datetime.utcnow().isoformat()}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:16]

    def scan_resources(
        self,
        resources: List[Dict[str, Any]],
        provider: CloudProvider,
        rule_ids: Optional[List[str]] = None,
    ) -> ScanResult:
        start_time = datetime.utcnow()
        all_findings = []
        errors = []
        rules_applied = set()

        for resource in resources:
            try:
                resource_type = resource.get("ResourceType", "unknown")
                findings = self.evaluate_resource(
                    resource, resource_type, provider, rule_ids
                )
                all_findings.extend(findings)
                for finding in findings:
                    rules_applied.add(finding.rule_id)
            except Exception as e:
                errors.append(f"Error processing resource: {str(e)}")

        duration = (datetime.utcnow() - start_time).total_seconds()

        summary = {
            "total_findings": len(all_findings),
            "critical": len(
                [f for f in all_findings if f.severity == SeverityLevel.CRITICAL]
            ),
            "high": len([f for f in all_findings if f.severity == SeverityLevel.HIGH]),
            "medium": len(
                [f for f in all_findings if f.severity == SeverityLevel.MEDIUM]
            ),
            "low": len([f for f in all_findings if f.severity == SeverityLevel.LOW]),
            "compliant": len(resources) - len(all_findings),
        }

        return ScanResult(
            scan_id=self._generate_scan_id(),
            timestamp=start_time,
            cloud_provider=provider,
            total_resources=len(resources),
            scanned_resources=len(resources),
            findings=all_findings,
            summary=summary,
            duration_seconds=duration,
            rules_applied=list(rules_applied),
            errors=errors,
        )

    def _generate_scan_id(self) -> str:
        return f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:8]}"

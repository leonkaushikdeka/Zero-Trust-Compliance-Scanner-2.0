from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import os
from datetime import datetime


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ComplianceRule:
    rule_id: str
    name: str
    description: str
    severity: SeverityLevel
    benchmark: str
    version: str
    category: str
    remediation: str
    check_function: str
    cloud_provider: CloudProvider
    tags: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    resource_id: str
    resource_type: str
    resource_name: str
    status: ComplianceStatus
    severity: SeverityLevel
    message: str
    remediation: str
    evidence: Dict[str, Any]
    timestamp: datetime
    cloud_provider: CloudProvider
    region: Optional[str] = None
    account_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    scan_id: str
    timestamp: datetime
    cloud_provider: CloudProvider
    total_resources: int
    scanned_resources: int
    findings: List[Finding]
    summary: Dict[str, int]
    duration_seconds: float
    rules_applied: List[str]
    errors: List[str] = field(default_factory=list)


@dataclass
class ScannerConfig:
    enabled_providers: List[CloudProvider] = field(default_factory=list)
    aws_regions: List[str] = field(
        default_factory=lambda: ["us-east-1", "us-west-2", "eu-west-1"]
    )
    azure_subscriptions: List[str] = field(default_factory=list)
    gcp_projects: List[str] = field(default_factory=list)
    kubernetes_clusters: List[str] = field(default_factory=list)
    terraform_paths: List[str] = field(
        default_factory=lambda: ["./terraform", "./infrastructure"]
    )
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    exclude_resources: List[str] = field(default_factory=list)
    exclude_rules: List[str] = field(default_factory=list)
    batch_size: int = 100
    timeout_seconds: int = 300
    parallel_scans: int = 10
    enable_real_time: bool = True
    webhook_url: Optional[str] = None
    sns_topic_arn: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    s3_bucket: Optional[str] = None
    dynamodb_table: Optional[str] = None
    custom_rules_path: Optional[str] = None
    cache_ttl_seconds: int = 3600
    dry_run: bool = False
    verbose: bool = False


class ConfigManager:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.environ.get(
            "COMPLIANCE_SCANNER_CONFIG", "config/scanner_config.json"
        )
        self.config: Optional[ScannerConfig] = None

    def load_config(self) -> ScannerConfig:
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                config_data = json.load(f)
            self.config = self._parse_config(config_data)
        else:
            self.config = ScannerConfig()
        self._apply_environment_overrides()
        return self.config

    def _parse_config(self, data: Dict[str, Any]) -> ScannerConfig:
        return ScannerConfig(
            enabled_providers=[
                CloudProvider(p) for p in data.get("enabled_providers", [])
            ],
            aws_regions=data.get(
                "aws_regions", ["us-east-1", "us-west-2", "eu-west-1"]
            ),
            azure_subscriptions=data.get("azure_subscriptions", []),
            gcp_projects=data.get("gcp_projects", []),
            kubernetes_clusters=data.get("kubernetes_clusters", []),
            terraform_paths=data.get(
                "terraform_paths", ["./terraform", "./infrastructure"]
            ),
            severity_threshold=SeverityLevel(data.get("severity_threshold", "low")),
            exclude_resources=data.get("exclude_resources", []),
            exclude_rules=data.get("exclude_rules", []),
            batch_size=data.get("batch_size", 100),
            timeout_seconds=data.get("timeout_seconds", 300),
            parallel_scans=data.get("parallel_scans", 10),
            enable_real_time=data.get("enable_real_time", True),
            webhook_url=data.get("webhook_url"),
            sns_topic_arn=data.get("sns_topic_arn"),
            slack_webhook_url=data.get("slack_webhook_url"),
            s3_bucket=data.get("s3_bucket"),
            dynamodb_table=data.get("dynamodb_table"),
            custom_rules_path=data.get("custom_rules_path"),
            cache_ttl_seconds=data.get("cache_ttl_seconds", 3600),
            dry_run=data.get("dry_run", False),
            verbose=data.get("verbose", False),
        )

    def _apply_environment_overrides(self):
        if not self.config:
            return

        env_overrides = {
            "AWS_REGIONS": ("aws_regions", lambda x: x.split(",")),
            "AZURE_SUBSCRIPTIONS": ("azure_subscriptions", lambda x: x.split(",")),
            "GCP_PROJECTS": ("gcp_projects", lambda x: x.split(",")),
            "SEVERITY_THRESHOLD": ("severity_threshold", lambda x: SeverityLevel(x)),
            "TIMEOUT_SECONDS": ("timeout_seconds", int),
            "DRY_RUN": ("dry_run", lambda x: x.lower() == "true"),
            "VERBOSE": ("verbose", lambda x: x.lower() == "true"),
        }

        for env_var, (attr, parser) in env_overrides.items():
            value = os.environ.get(f"COMPLIANCE_{env_var}")
            if value:
                setattr(self.config, attr, parser(value))

    def save_config(self, config: ScannerConfig, path: Optional[str] = None):
        path = path or self.config_path
        os.makedirs(os.path.dirname(path), exist_ok=True)

        config_data = {
            "enabled_providers": [p.value for p in config.enabled_providers],
            "aws_regions": config.aws_regions,
            "azure_subscriptions": config.azure_subscriptions,
            "gcp_projects": config.gcp_projects,
            "kubernetes_clusters": config.kubernetes_clusters,
            "terraform_paths": config.terraform_paths,
            "severity_threshold": config.severity_threshold.value,
            "exclude_resources": config.exclude_resources,
            "exclude_rules": config.exclude_rules,
            "batch_size": config.batch_size,
            "timeout_seconds": config.timeout_seconds,
            "parallel_scans": config.parallel_scans,
            "enable_real_time": config.enable_real_time,
            "webhook_url": config.webhook_url,
            "sns_topic_arn": config.sns_topic_arn,
            "slack_webhook_url": config.slack_webhook_url,
            "s3_bucket": config.s3_bucket,
            "dynamodb_table": config.dynamodb_table,
            "custom_rules_path": config.custom_rules_path,
            "cache_ttl_seconds": config.cache_ttl_seconds,
            "dry_run": config.dry_run,
            "verbose": config.verbose,
        }

        with open(path, "w") as f:
            json.dump(config_data, f, indent=2)

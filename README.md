<div align="center">

# 🛡️ Zero-Trust Compliance Scanner

**Automated Multi-Cloud Security Compliance for Enterprise Infrastructure**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CIS Benchmarks](https://img.shields.io/badge/CIS-Benchmarks-27%20rules-green.svg)](#cis-compliance-rules)
[![Multi-Cloud](https://img.shields.io/badge/Multi--Cloud-AWS%20%7C%20Azure%20%7C%20GCP%20%7C%20K8s%20%7C%20Terraform-orange.svg)](#supported-platforms)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Supported Platforms](#-supported-platforms)
- [CIS Compliance Rules](#-cis-compliance-rules)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [CI/CD Integration](#-cicd-integration)
- [Configuration](#-configuration)
- [Alerting](#-alerting)
- [API Reference](#-api-reference)
- [Deployment](#-deployment)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

---

## 🎯 Overview

The **Zero-Trust Compliance Scanner** is a production-grade, serverless security compliance solution that automatically scans your infrastructure for CIS benchmark violations. It integrates seamlessly into CI/CD pipelines to prevent misconfigurations from reaching production, implementing a true zero-trust security model.

### What is Zero-Trust Compliance?

Zero-trust compliance means:
- **Never trust, always verify** - Every resource is checked against security benchmarks
- **Assume breach** - Continuous monitoring and alerting
- **Least privilege access** - Validate configurations before deployment
- **Comprehensive coverage** - Multi-cloud support with unified policies

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **27 Pre-built Rules** | CIS benchmark rules for AWS, Azure, GCP, Kubernetes, and Terraform |
| ☁️ **Multi-Cloud Support** | Unified compliance scanning across all major cloud platforms |
| 🚀 **Serverless Architecture** | AWS Lambda-based for automatic scaling and cost efficiency |
| 🔗 **CI/CD Integration** | Native integration with GitHub Actions, GitLab CI, Azure DevOps, and Jenkins |
| 📊 **Comprehensive Reporting** | JSON, HTML, and dashboard-ready reports with compliance scores |
| 🔔 **Real-time Alerting** | SNS, Slack, PagerDuty, and AWS Security Hub integration |
| ⚡ **High Performance** | Parallel scanning with configurable batch sizes |
| 🔧 **Extensible** | Easy to add custom rules and integrations |
| 📈 **Compliance Scoring** | Quantitative compliance metrics and trends |
| 🔒 **Security First** | Encrypted data storage, KMS integration, and audit logging |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ZERO-TRUST COMPLIANCE SCANNER                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐            │
│  │   CI/CD TRIGGERS│   │  SCHEDULED SCAN │   │  EVENT TRIGGERS │            │
│  │   (GitHub/GitLab│   │  (EventBridge)  │   │  (Config Rules) │            │
│  │    Azure/Jenkins│   │                 │   │                 │            │
│  └────────┬────────┘   └────────┬────────┘   └────────┬────────┘            │
│           │                     │                     │                      │
│           └─────────────────────┼─────────────────────┘                      │
│                                 │                                            │
│                                 ▼                                            │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                    AWS LAMBDA FUNCTIONS                                │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐        │   │
│  │  │ Main Scanner    │  │ CI/CD Scanner   │  │ Terraform       │        │   │
│  │  │ Function        │  │ Function        │  │ Scanner         │        │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘        │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                 │                                            │
│         ┌───────────────────────┼───────────────────────┐                   │
│         │                       │                       │                   │
│         ▼                       ▼                       ▼                   │
│  ┌─────────────┐       ┌─────────────┐       ┌─────────────────┐            │
│  │   RULE      │       │  RESOURCE   │       │   ALERTING &    │            │
│  │   ENGINE    │◄─────►│  COLLECTORS │◄─────►│   REPORTING     │            │
│  │ (27 Rules)  │       │ (Multi-Cloud)│       │ (SNS/Slack/HTML)│            │
│  └─────────────┘       └─────────────┘       └─────────────────┘            │
│                                 │                                            │
│                                 ▼                                            │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                    COMPLIANCE DATASTORE                                 │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐                 │   │
│  │  │ DynamoDB    │  │     S3      │  │  CloudWatch     │                 │   │
│  │  │ (Results)   │  │  (Reports)  │  │   (Logs)        │                 │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘                 │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## ☁️ Supported Platforms

| Platform | Status | Rules | Description |
|----------|--------|-------|-------------|
| **AWS** | ✅ Stable | 10 | CIS AWS Foundations Benchmark v1.2.0 |
| **Azure** | ✅ Stable | 4 | CIS Microsoft Azure Foundations v1.3.0 |
| **GCP** | ✅ Stable | 4 | CIS Google Cloud Platform v1.0.0 |
| **Kubernetes** | ✅ Stable | 5 | CIS Kubernetes Benchmark v1.6.0 |
| **Terraform** | ✅ Stable | 4 | Infrastructure as Code security |

---

## 📋 CIS Compliance Rules

### AWS Rules (CIS AWS Foundations Benchmark v1.2.0)

| ID | Severity | Category | Description | Remediation |
|----|----------|----------|-------------|-------------|
| **S3-1** | 🔴 CRITICAL | Storage | S3 buckets should have all public access blocked | Enable S3 Block Public Access configuration |
| **IAM-1** | 🟠 HIGH | Identity | IAM password policy should require minimum 14 characters | Update password policy complexity requirements |
| **IAM-2** | 🟠 HIGH | Identity | All IAM users should have MFA enabled | Enable MFA for all IAM users |
| **IAM-3** | 🔴 CRITICAL | Identity | IAM roles should not allow wildcard principals | Restrict trust policies to specific principals |
| **EC2-1** | 🔴 CRITICAL | Compute | Security groups should not allow unrestricted SSH (0.0.0.0/0:22) | Modify security group to restrict source IPs |
| **EC2-2** | 🟠 HIGH | Compute | EBS volumes should have encryption enabled | Enable encryption for EBS volumes |
| **EC2-3** | 🟠 HIGH | Compute | AMIs should not be publicly shared | Remove public sharing of AMIs |
| **RDS-1** | 🔴 CRITICAL | Database | RDS instances should not be publicly accessible | Disable public accessibility |
| **KMS-1** | 🟡 MEDIUM | Security | KMS keys should be enabled for encryption/decryption | Configure key usage |
| **CWL-1** | 🟡 MEDIUM | Logging | CloudTrail logs should be retained for 365 days | Update retention period |

### Azure Rules (CIS Microsoft Azure Foundations v1.3.0)

| ID | Severity | Category | Description | Remediation |
|----|----------|----------|-------------|-------------|
| **AZURE-1** | 🟠 HIGH | Storage | Storage accounts should require HTTPS only | Enable secure transfer required |
| **AZURE-2** | 🔴 CRITICAL | Network | NSG rules should not allow unrestricted management ports | Restrict NSG rules to specific source IPs |
| **AZURE-3** | 🔴 CRITICAL | Storage | Blob storage should have public access disabled | Disable public blob access |
| **AZURE-4** | 🟠 HIGH | Security | Microsoft Defender for Cloud should be enabled | Enable Defender for Cloud with Standard tier |

### GCP Rules (CIS Google Cloud Platform Foundation v1.0.0)

| ID | Severity | Category | Description | Remediation |
|----|----------|----------|-------------|-------------|
| **GCP-1** | 🔴 CRITICAL | Network | Firewall rules should not allow unrestricted SSH/RDP (0.0.0.0/0) | Modify firewall rules to restrict access |
| **GCP-2** | 🟠 HIGH | Storage | Storage buckets should use uniform bucket-level access | Enable uniform bucket-level access |
| **GCP-3** | 🟡 MEDIUM | Storage | Storage buckets should use CMEK encryption | Configure customer-managed encryption keys |
| **GCP-4** | 🟠 HIGH | Compute | Compute instances should have OS login enabled | Enable OS login on instances |

### Kubernetes Rules (CIS Kubernetes Benchmark v1.6.0)

| ID | Severity | Category | Description | Remediation |
|----|----------|----------|-------------|-------------|
| **K8S-1** | 🔴 CRITICAL | Pod Security | Pods should not run with privileged containers | Remove privileged container settings |
| **K8S-2** | 🟠 HIGH | Pod Security | Containers should use read-only root filesystem | Set readOnlyRootFilesystem to true |
| **K8S-3** | 🟠 HIGH | Pod Security | Pods should run as non-root user | Configure runAsNonRoot in security context |
| **K8S-4** | 🟡 MEDIUM | Network | Namespaces should have network policies defined | Create NetworkPolicy resources |
| **K8S-5** | 🟡 MEDIUM | Pod Security | Pods should have seccomp profile configured | Configure seccomp profile |

### Terraform Rules (Custom Security Rules)

| ID | Severity | Category | Description | Remediation |
|----|----------|----------|-------------|-------------|
| **TF-1** | 🟠 HIGH | Storage | S3 buckets should have versioning enabled | Enable versioning on S3 resources |
| **TF-2** | 🟡 MEDIUM | Logging | S3 buckets should have server access logging enabled | Enable logging configuration |
| **TF-3** | 🟠 HIGH | Database | Database resources should have backup configuration | Configure backup_retention_period |
| **TF-4** | 🔴 CRITICAL | Security | Terraform should not contain hardcoded secrets | Use environment variables or secrets manager |

---

## 🚀 Quick Start

### Prerequisites

- **Python**: 3.11 or higher
- **AWS CLI**: Configured with appropriate permissions
- **Terraform**: 1.0 or higher
- **Git**: Latest version

### 5-Minute Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/zero-trust-compliance-scanner.git
cd zero-trust-compliance-scanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run your first scan
python -c "
from core.config import *
from core.rule_engine import *

engine = RuleEngine()
resources = [
    {'Id': 'sg-1', 'Name': 'open-ssh', 'ResourceType': 'AWS::EC2::SecurityGroup',
     'IpPermissions': [{'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'FromPort': 22, 'ToPort': 22}],
     'Region': 'us-east-1'},
    {'Id': 'bucket-1', 'Name': 'secure-bucket', 'ResourceType': 'AWS::S3::Bucket',
     'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 
                                         'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}},
]

result = engine.scan_resources(resources, CloudProvider.AWS)
print(f'Resources: {result.total_resources}')
print(f'Findings: {result.summary[\"total_findings\"]}')
print(f'Compliant: {result.summary[\"compliant\"]}')
print(f'Compliance Score: {(result.summary[\"compliant\"]/result.total_resources)*100:.1f}%')
"
```

**Expected Output:**
```
Resources: 2
Findings: 1
Compliant: 1
Compliance Score: 50.0%
```

---

## 📦 Installation

### Option 1: pip (Recommended)

```bash
# Install from PyPI
pip install zerotrust-compliance-scanner

# Or install from source
pip install -e .
```

### Option 2: Docker

```bash
# Pull the official image
docker pull public.ecr.aws/zerotrust/compliance-scanner:latest

# Run a scan
docker run --rm \
  -e AWS_PROFILE=default \
  -v $(pwd)/reports:/app/reports \
  public.ecr.aws/zerotrust/compliance-scanner:latest \
  scan --provider aws --output-format json --output /app/reports/report.json
```

### Option 3: AWS Lambda Layer

```bash
# Package as Lambda layer
cd src
zip -r ../layer.zip .
aws lambda publish-layer-version \
  --layer-name zerotrust-compliance \
  --zip-file fileb://layer.zip \
  --compatible-runtimes python3.11
```

---

## 💻 Usage

### CLI Commands

```bash
# Run a compliance scan
compliance-scan scan --provider aws

# Scan with specific regions
compliance-scan scan --provider aws --regions us-east-1 us-west-2

# Scan with severity threshold
compliance-scan scan --provider aws --severity-threshold high

# Generate CI/CD workflow
compliance-scan generate --provider github --output .github/workflows/compliance.yml

# Validate Terraform plan
compliance-scan scan-terraform --plan-file plan.json

# Show compliance summary
compliance-scan summary --provider aws
```

### Python API

```python
from src.config import ScannerConfig, CloudProvider
from src.scanners.compliance_scanner import ComplianceScanner

# Initialize scanner
config = ScannerConfig(
    enabled_providers=[CloudProvider.AWS],
    aws_regions=["us-east-1", "us-west-2"],
    severity_threshold=SeverityLevel.LOW,
    dry_run=False,
    verbose=True,
)

scanner = ComplianceScanner(config)

# Run full scan
results = scanner.run_scan()

# Get summary
summary = scanner.get_compliance_summary(results)
print(f"Overall Score: {summary['overall_score']}%")
print(f"Critical Findings: {len(summary['critical_findings'])}")

# Run CI/CD scan
ci_cd_report = scanner.run_ci_cd_scan(
    provider=CloudProvider.AWS,
    commit_sha="abc123def",
    pipeline_id="build-456"
)

print(f"CI/CD Score: {ci_cd_report['compliance_score']}%")
print(f"Pass: {ci_cd_report['pass']}")
```

---

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
name: Zero-Trust Compliance Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ env.AWS_REGION }}
          role-to-assume: ${{ secrets.COMPLIANCE_SCAN_ROLE_ARN }}
      
      - name: Run Compliance Scan
        run: |
          pip install zerotrust-compliance-scanner
          compliance-scan scan \
            --provider aws \
            --commit-sha ${{ github.sha }} \
            --output-format json \
            --threshold-score 80 \
            > compliance_report.json
          
          # Upload report as artifact
          cp compliance_report.json "$GITHUB_STEP_SUMMARY.md"
      
      - name: Check Compliance Gate
        run: |
          score=$(cat compliance_report.json | jq -r '.compliance_score')
          pass=$(cat compliance_report.json | jq -r '.pass')
          
          if [ "$pass" == "false" ]; then
            echo "❌ Compliance check FAILED"
            cat compliance_report.json | jq '.findings[] | select(.severity == "critical" or .severity == "high")'
            exit 1
          elif [ $(echo "$score < 80" | bc) -eq 1 ]; then
            echo "⚠️  Compliance score ($score%) below threshold (80%)"
            exit 1
          else
            echo "✅ Compliance check PASSED (Score: $score%)"
          fi
      
      - name: Upload Compliance Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: compliance-report
          path: compliance_report.json
```

### GitLab CI

```yaml
stages:
  - security
  - quality

compliance_scan:
  image: public.ecr.aws/zerotrust/compliance-scanner:latest
  stage: security
  script:
    - |
      compliance-scan scan \
        --provider aws \
        --commit-sha $CI_COMMIT_SHA \
        --output-format json \
        --threshold-score 80 \
        > compliance_report.json
      
      score=$(cat compliance_report.json | jq -r '.compliance_score')
      pass=$(cat compliance_report.json | jq -r '.pass')
      
      echo "Compliance Score: $score%"
      echo "Findings: $(cat compliance_report.json | jq -r '.findings | length')"
      
      if [ "$pass" == "false" ]; then
        echo "❌ Compliance check FAILED"
        cat compliance_report.json | jq '.findings'
        exit 1
      elif [ $(echo "$score < 80" | bc) -eq 1 ]; then
        echo "⚠️  Score below threshold"
        exit 1
      fi
  artifacts:
    paths:
      - compliance_report.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Azure DevOps

```yaml
trigger:
  - main

variables:
  awsRegion: 'eastus'
  complianceThreshold: 80

stages:
  - stage: ComplianceScan
    jobs:
      - job: ComplianceScan
        pool:
          vmImage: ubuntu-latest
        steps:
          - checkout: self
            fetchDepth: 0
          
          - task: ConfigureAWSCredentials@1
            inputs:
              awsConnection: 'AWS-Connection'
              awsRegion: $(awsRegion)
          
          - script: |
              pip install zerotrust-compliance-scanner
              compliance-scan scan \
                --provider aws \
                --commit-sha $(Build.SourceVersion) \
                --output-format json \
                --threshold-score $(complianceThreshold) \
                > $(Build.ArtifactStagingDirectory)/compliance_report.json
              cat $(Build.ArtifactStagingDirectory)/compliance_report.json
            displayName: Run Compliance Scan
          
          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: $(Build.ArtifactStagingDirectory)/compliance_report.json
              artifactName: compliance-report
```

---

## ⚙️ Configuration

### Configuration File

Create a `config.json` file:

```json
{
  "enabled_providers": ["aws", "azure", "gcp", "terraform"],
  "aws_regions": ["us-east-1", "us-west-2", "eu-west-1"],
  "azure_subscriptions": ["sub-12345678-1234-1234-1234-123456789012"],
  "gcp_projects": ["my-project-123456"],
  "severity_threshold": "low",
  "batch_size": 100,
  "timeout_seconds": 300,
  "parallel_scans": 10,
  "exclude_resources": ["arn:aws:ec2:*:*:security-group/sg-ignored"],
  "exclude_rules": ["EC2-3"],
  "dry_run": false,
  "verbose": true
}
```

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AWS_REGION` | AWS region for API calls | `us-east-1` | No |
| `AWS_PROFILE` | AWS profile name | `default` | No |
| `CONFIG_S3_BUCKET` | S3 bucket for scanner config | - | No |
| `SNS_TOPIC_ARN` | SNS topic ARN for alerts | - | No |
| `SLACK_WEBHOOK_URL` | Slack webhook URL | - | No |
| `PAGERDUTY_ROUTING_KEY` | PagerDuty routing key | - | No |
| `DYNAMODB_TABLE` | DynamoDB table for results | `compliance-scan-results` | No |
| `S3_BUCKET` | S3 bucket for reports | - | No |
| `KMS_KEY_ID` | KMS key for encryption | - | No |
| `LOG_LEVEL` | Logging level | `INFO` | No |

---

## 🔔 Alerting

### AWS SNS

```python
from src.config import ScannerConfig
from src.utils.alerting import AlertManager

config = ScannerConfig(
    sns_topic_arn="arn:aws:sns:us-east-1:123456789012:compliance-alerts"
)
alert_manager = AlertManager(config)
```

### Slack

```python
config = ScannerConfig(
    slack_webhook_url="https://hooks.slack.com/services/xxx/yyy/zzz"
)
alert_manager = AlertManager(config)
```

### PagerDuty

```python
from src.utils.alerting import PagerDutyIntegration

pagerduty = PagerDutyIntegration(
    api_key="your-api-key",
    service_id="your-service-id"
)

pagerduty.trigger_incident(finding, routing_key="your-routing-key")
```

### AWS Security Hub

```python
from src.utils.alerting import SecurityHubIntegration

securityhub = SecurityHubIntegration(region="us-east-1")
securityhub.import_findings(findings, aws_account_id="123456789012")
```

---

## 📚 API Reference

### ComplianceScanner

```python
from src.scanners.compliance_scanner import ComplianceScanner
from src.config import ScannerConfig, CloudProvider

# Initialize
scanner = ComplianceScanner(config: Optional[ScannerConfig] = None)

# Methods
results = scanner.run_scan(
    providers: Optional[List[CloudProvider]] = None,
    rule_ids: Optional[List[str]] = None,
    resource_filter: Optional[Dict[str, Any]] = None
) -> Dict[CloudProvider, ScanResult]

report = scanner.run_ci_cd_scan(
    provider: CloudProvider,
    commit_sha: str,
    pipeline_id: str
) -> Dict[str, Any]

summary = scanner.get_compliance_summary(
    results: Dict[CloudProvider, ScanResult]
) -> Dict[str, Any]
```

### RuleEngine

```python
from src.rule_engine import RuleEngine

engine = RuleEngine()

# Methods
rules = engine.get_rules(
    cloud_provider: Optional[CloudProvider] = None,
    category: Optional[str] = None,
    severity: Optional[SeverityLevel] = None
) -> List[ComplianceRule]

findings = engine.evaluate_resource(
    resource: Dict[str, Any],
    resource_type: str,
    provider: CloudProvider,
    rule_ids: Optional[List[str]] = None
) -> List[Finding]

result = engine.scan_resources(
    resources: List[Dict[str, Any]],
    provider: CloudProvider,
    rule_ids: Optional[List[str]] = None
) -> ScanResult
```

### Data Classes

```python
@dataclass
class ScannerConfig:
    enabled_providers: List[CloudProvider]
    aws_regions: List[str]
    severity_threshold: SeverityLevel
    batch_size: int
    timeout_seconds: int
    parallel_scans: int
    dry_run: bool
    verbose: bool

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
    rules_applied: List[str    errors: List[str]

@dataclass]

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
    region: Optional[str]
    account_id: Optional[str]
```

---

## 🚢 Deployment

### AWS Terraform Deployment

```bash
# Navigate to Terraform directory
cd deploy/terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var="aws_region=us-east-1" -var="alert_email=security@example.com"

# Apply deployment
terraform apply -var="aws_region=us-east-1" -var="alert_email=security@example.com"
```

### Terraform Variables

```hcl
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "zerotrust-compliance"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
}

variable "alert_email" {
  description = "Email address for compliance alerts"
  type        = string
  default     = "security@example.com"
}
```

### Package Lambda Function

```bash
# Create deployment package
cd src
zip -r ../deploy/lambda.zip . -x "*.pyc" "__pycache__/*"
cd ..

# Update Lambda function
aws lambda update-function-code \
    --function-name zerotrust-compliance-scanner \
    --zip-file fileb://deploy/lambda.zip
```

---

## 🧪 Testing

### Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html --cov-report=term-missing

# Run specific test categories
pytest tests/unit/ -v
pytest tests/integration/ -v

# Run with verbose output
pytest tests/ -vv --tb=short
```

### Test Configuration

```ini
# pytest.ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/new-rule`)
3. **Add** tests for your changes
4. **Run** the test suite (`pytest`)
5. **Submit** a pull request

### Adding Custom Rules

```python
from src.config import ComplianceRule, SeverityLevel, CloudProvider
from src.rule_engine import RuleEngine

# Define custom rule
custom_rule = ComplianceRule(
    rule_id="CUSTOM-1",
    name="Custom Security Check",
    description="Description of your custom check",
    severity=SeverityLevel.HIGH,
    benchmark="Custom Benchmark",
    version="1.0.0",
    category="Custom",
    remediation="How to fix the issue",
    check_function="custom_check_function",
    cloud_provider=CloudProvider.AWS,
    tags=["custom", "security"],
    metadata={"custom_field": "value"}
)

# Register with rule engine
engine = RuleEngine()
engine.register_rule(custom_rule)
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/your-org/zero-trust-compliance-scanner/issues)
- **Documentation**: See the [docs](docs/) directory
- **AWS Support**: For deployment issues, contact AWS Support
- **Discussions**: [Join our GitHub Discussions](https://github.com/your-org/zero-trust-compliance-scanner/discussions)

---

## 🙏 Acknowledgments

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - For compliance standards
- [AWS Security Hub](https://aws.amazon.com/security-hub/) - For findings integration
- [The Open Source Community](https://github.com/) - For continuous contributions

---

<div align="center">

**Made with 🛡️ for a more secure cloud**

*Zero-Trust Compliance Scanner - Automating Security Compliance*

</div>

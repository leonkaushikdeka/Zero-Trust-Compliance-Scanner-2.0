# ADR-002: Use CIS Benchmarks as Primary Compliance Framework

## Status

Accepted

## Context

The compliance scanner needs a well-defined, industry-standard set of rules to evaluate infrastructure security. We evaluated several compliance frameworks:

1. **CIS Benchmarks** - Center for Internet Security benchmarks
2. **NIST CSF** - NIST Cybersecurity Framework
3. **SOC 2** - Service Organization Control 2
4. **PCI-DSS** - Payment Card Industry Data Security Standard
5. **HIPAA** - Health Insurance Portability and Accountability Act
6. **Custom rules** - Organization-specific security policies

## Decision

We chose CIS Benchmarks as the primary compliance framework, with extensibility for custom rules.

## Consequences

### Positive

- **Industry standard** - Widely recognized and accepted benchmark
- **Comprehensive coverage** - Detailed rules for major platforms
- **Multi-cloud support** - Benchmarks for AWS, Azure, GCP, Kubernetes
- **Clear remediation** - Each rule includes specific remediation steps
- **Maturity** - Well-established with regular updates
- **Vendor neutral** - Not tied to any single cloud provider

### Negative

- **Broad scope** - Some rules may not apply to all organizations
- **Update frequency** - Requires regular updates to stay current
- **Platform coverage** - May not cover all specialized platforms
- **Complexity** - Hundreds of rules can be overwhelming

### Mitigations

- Implement rule filtering by severity and category
- Allow custom rule definitions for organization-specific policies
- Support rule enable/disable configuration
- Provide compliance score summaries

## Implementation

CIS Benchmark rules are implemented in `src/core/rule_engine.py`:

- 27 rules across 5 platforms (AWS, Azure, GCP, Kubernetes, Terraform)
- Each rule includes: ID, name, description, severity, remediation, tags
- Severity levels: Critical, High, Medium, Low, Info
- CloudProvider enum for platform-specific filtering

Example rule structure:
```python
"AWS-S3-001": ComplianceRule(
    rule_id="AWS-S3-001",
    name="S3 Bucket Should Have Public Access Blocked",
    description="S3 buckets should block public access",
    severity=SeverityLevel.CRITICAL,
    benchmark="CIS AWS Foundations Benchmark",
    version="1.2.0",
    category="Storage",
    remediation="Enable S3 Block Public Access at account level",
    check_function="check_s3_public_access_block",
    cloud_provider=CloudProvider.AWS,
    tags=["s3", "public-access", "data-protection"],
)
```

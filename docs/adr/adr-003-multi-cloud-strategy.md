# ADR-003: Support Multi-Cloud Compliance Scanning

## Status

Accepted

## Context

Enterprise organizations typically deploy infrastructure across multiple cloud providers. The compliance scanner needs to evaluate security posture consistently across all platforms. We evaluated:

1. **Single-cloud focus** - Only support AWS (market leader)
2. **Multi-cloud support** - AWS, Azure, GCP, Kubernetes
3. **Cloud-agnostic** - Abstract platform differences (more complex)
4. **Hybrid cloud** - Include on-premises infrastructure

## Decision

We chose to implement multi-cloud support for AWS, Azure, GCP, Kubernetes, and Terraform IaC.

## Consequences

### Positive

- **Customer coverage** - Supports enterprise multi-cloud strategies
- **Consistent posture** - Unified compliance view across providers
- **Terraform support** - Scan infrastructure-as-code before deployment
- **Kubernetes support** - Container orchestration security
- **Market differentiation** - Competes with enterprise-focused tools

### Negative

- **Increased complexity** - More code to maintain and test
- **API differences** - Each cloud has unique APIs and terminology
- **Rule alignment** - CIS rules vary by platform
- **Dependency management** - Multiple SDKs increase package size

### Mitigations

- Use abstracted resource models (normalize to common format)
- Platform-specific collectors with shared interfaces
- Conditional imports to reduce cold start impact
- Extensive unit testing for each platform

## Implementation

Multi-cloud support is implemented in `src/collectors/resource_collectors.py`:

### AWS Collector
- EC2 instances, security groups, AMIs
- S3 buckets, access controls
- IAM users, roles, policies
- KMS keys, RDS instances
- CloudTrail, Config rules

### Azure Collector
- Virtual machines, network security groups
- Storage accounts
- Azure Active Directory
- Security Center findings

### GCP Collector
- Compute Engine instances
- Cloud Storage buckets
- Firewall rules
- IAM policies

### Kubernetes Collector
- Pod security policies
- Deployment configurations
- Network policies
- RBAC configurations

### Terraform Collector
- Parse HCL2 Terraform plans
- Evaluate resources before deployment
- Support for modules and variables

### Normalization

Each collector normalizes resources to a common format:
```python
{
    "Id": "resource-id",
    "Name": "resource-name",
    "ResourceType": "AWS::EC2::Instance",
    "Region": "us-east-1",
    "Tags": [...],
    "Configuration": {...},
}
```

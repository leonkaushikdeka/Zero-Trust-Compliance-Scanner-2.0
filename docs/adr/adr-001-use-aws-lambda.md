# ADR-001: Use AWS Lambda for Serverless Architecture

## Status

Accepted

## Context

The Zero-Trust Compliance Scanner needs to run as a scalable, cost-effective service that can scan infrastructure on-demand and on-schedule. We evaluated several deployment options:

1. **AWS Lambda** - Serverless compute with automatic scaling
2. **ECS/Fargate** - Container-based with more control
3. **EC2** - Full control but requires more management
4. **Kubernetes** - For organizations with existing K8s infrastructure

## Decision

We chose AWS Lambda as the primary compute platform for the compliance scanner.

## Consequences

### Positive

- **Automatic scaling** - Handles variable load without manual intervention
- **Cost-effective** - Pay per invocation, no idle capacity costs
- **Managed infrastructure** - No server patching or maintenance
- **Native AWS integration** - Easy integration with CloudWatch, S3, DynamoDB, SNS
- **Cold start optimization** - Fast enough for most use cases
- **Event-driven** - Natural fit for scheduled scans and CI/CD triggers

### Negative

- **Execution time limit** - 15 minutes max (may require chunking for large scans)
- **Cold starts** - Initial latency on first invocation
- **Package size limits** - 250MB deployment package size
- **No stateful execution** - Must use external state (DynamoDB, S3)

### Mitigations

- Use Lambda Layers for common dependencies to reduce package size
- Implement incremental scanning for large infrastructure
- Use provisioned concurrency for latency-sensitive deployments
- Design for stateless execution with external state stores

## Implementation

The Lambda handlers are located in `src/api/lambda_handlers.py`:

- `main_handler` - General scan invocations via API Gateway
- `scheduled_handler` - CloudWatch Event rule for scheduled scans
- `cicd_handler` - CI/CD pipeline integration
- `terraform_handler` - Terraform plan file scanning

Deployment is managed via Terraform in `deploy/terraform/main.tf`.

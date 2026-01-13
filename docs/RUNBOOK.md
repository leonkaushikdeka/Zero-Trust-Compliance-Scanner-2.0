# Zero-Trust Compliance Scanner - Operations Runbook

## Table of Contents

1. [Overview](#1-overview)
2. [Daily Operations](#2-daily-operations)
3. [Common Procedures](#3-common-procedures)
4. [Troubleshooting](#4-troubleshooting)
5. [Incident Response](#5-incident-response)
6. [Maintenance Tasks](#6-maintenance-tasks)
7. [Escalation](#7-escalation)

---

## 1. Overview

### 1.1 System Description

The Zero-Trust Compliance Scanner is an automated security compliance monitoring solution that:

- Scans AWS, Azure, GCP, Kubernetes, and Terraform resources
- Evaluates resources against 27 CIS benchmark rules
- Integrates with CI/CD pipelines
- Generates real-time alerts via SNS, Slack, and PagerDuty
- Stores compliance findings in DynamoDB and S3

### 1.2 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                  AWS Account: Production                │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │         AWS Lambda (scanner function)            │   │
│  │  - Memory: 512MB - 1GB                          │   │
│  │  - Timeout: 300 seconds                         │   │
│  │  - Runtime: Python 3.11                         │   │
│  └─────────────────────────────────────────────────┘   │
│                        │                              │
│         ┌──────────────┼──────────────┐               │
│         ▼              ▼              ▼               │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐        │
│  │ DynamoDB  │  │     S3    │  │  CloudWatch│        │
│  │ (Results) │  │ (Reports) │  │   (Logs)  │        │
│  └───────────┘  └───────────┘  └───────────┘        │
└─────────────────────────────────────────────────────────┘
```

### 1.3 Critical Components

| Component | Purpose | SLA |
|-----------|---------|-----|
| Lambda Function | Scan execution | 99.9% |
| DynamoDB | Results storage | 99.99% |
| S3 | Reports storage | 99.99% |
| SNS | Alert delivery | 99% |
| CloudWatch | Monitoring | 99.9% |

---

## 2. Daily Operations

### 2.1 Morning Health Check

```bash
#!/bin/bash
# daily_health_check.sh

echo "=== Zero-Trust Compliance Scanner Health Check ==="
echo "Date: $(date)"
echo ""

# Check Lambda function status
echo "1. Lambda Function Status:"
aws lambda get-function-configuration \
  --function-name zerotrust-compliance-scanner \
  --query '[FunctionName,State,LastUpdateStatus]' \
  --output table

# Check recent invocations
echo ""
echo "2. Recent Invocations (last 24h):"
aws lambda list-invocations \
  --function-name zerotrust-compliance-scanner \
  --count 20 \
  --output json | jq '.[-10:]'

# Check CloudWatch metrics
echo ""
echo "3. CloudWatch Metrics Summary:"
aws cloudwatch get-metric-statistics \
  --namespace "ZeroTrustComplianceScanner" \
  --metric-name "ScanCompleted" \
  --start-time "$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 86400 \
  --statistic Sum \
  --output json | jq '.Datapoints[0]'

# Check DynamoDB table status
echo ""
echo "4. DynamoDB Table Status:"
aws dynamodb describe-table \
  --table-name zerotrust-compliance-scan-results \
  --query '[TableName,TableStatus,ItemCount]' \
  --output table

# Check for errors in logs
echo ""
echo "5. Error Log Count (last 24h):"
aws logs filter-log-events \
  --log-group-name "/aws/lambda/zerotrust-compliance-scanner" \
  --start-time "$(date -u -v-1d +%s)000" \
  --end-time "$(date -u +%s)000" \
  --filter-pattern "ERROR" \
  --output json | jq '.events | length'
```

### 2.2 Daily Compliance Report Review

```python
# daily_report_review.py
import boto3
import json
from datetime import datetime, timedelta

def get_daily_compliance_report():
    """Generate and review daily compliance report."""
    s3 = boto3.client('s3')
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('zerotrust-compliance-scan-results')
    
    # Get yesterday's scans
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    
    response = table.query(
        IndexName='provider-timestamp-index',
        KeyConditionExpression="begins_with(#pk, :provider)"
    )
    
    # Calculate metrics
    total_scans = 0
    critical_findings = 0
    high_findings = 0
    
    for item in response.get('Items', []):
        total_scans += 1
        critical_findings += item.get('summary', {}).get('critical', 0)
        high_findings += item.get('summary', {}).get('high', 0)
    
    print(f"Daily Compliance Summary - {yesterday}")
    print(f"Total Scans: {total_scans}")
    print(f"Critical Findings: {critical_findings}")
    print(f"High Findings: {high_findings}")
    
    if critical_findings > 0:
        print("⚠️  ACTION REQUIRED: Critical findings detected!")
        send_alert_to_slack(f"Daily compliance report: {critical_findings} critical, {high_findings} high findings")
```

---

## 3. Common Procedures

### 3.1 Run Manual Scan

```bash
#!/bin/bash
# manual_scan.sh - Run a compliance scan on demand

PROVIDER=${1:-aws}
REGIONS=${2:-us-east-1}
OUTPUT_FILE="scan_$(date +%Y%m%d_%H%M%S).json"

echo "Starting manual compliance scan..."
echo "Provider: $PROVIDER"
echo "Regions: $REGIONS"
echo "Output: $OUTPUT_FILE"

# Invoke Lambda function
aws lambda invoke \
  --function-name zerotrust-compliance-scanner \
  --payload "{\"scan_type\": \"manual\", \"providers\": [\"$PROVIDER\"], \"regions\": [\"$REGIONS\"]}" \
  --invocation-type RequestResponse \
  --log-type Tail \
  $OUTPUT_FILE

# Check result
if [ $? -eq 0 ]; then
    echo "Scan completed successfully!"
    jq '.body' $OUTPUT_FILE | jq '.' > result.json
    cat result.json
else
    echo "Scan failed! Check logs."
fi
```

### 3.2 Update CIS Rules

```python
# update_rules.py
import boto3

def update_cis_rules(rule_updates):
    """
    Update CIS benchmark rules.
    
    Args:
        rule_updates: List of rule updates in format:
            [
                {
                    "rule_id": "S3-1",
                    "severity": "CRITICAL",
                    "description": "New description",
                    "remediation": "New remediation"
                }
            ]
    """
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('zerotrust-compliance-rules')
    
    for update in rule_updates:
        table.update_item(
            Key={'rule_id': update['rule_id']},
            UpdateExpression="SET #sev = :sev, #desc = :desc, #rem = :rem, #updated = :now",
            ExpressionAttributeNames={
                '#sev': 'severity',
                '#desc': 'description',
                '#rem': 'remediation',
                '#updated': 'last_updated'
            },
            ExpressionAttributeValues={
                ':sev': update['severity'],
                ':desc': update['description'],
                ':rem': update['remediation'],
                ':now': datetime.now().isoformat()
            }
        )
    
    print(f"Updated {len(rule_updates)} rules")

# Usage
update_cis_rules([
    {
        "rule_id": "EC2-1",
        "severity": "HIGH",  # Demoted from CRITICAL
        "description": "Updated description",
        "remediation": "Updated remediation"
    }
])
```

### 3.3 Configure Alert Channels

```python
# configure_alerts.py
import boto3

def add_slack_channel(webhook_url: str, channel_name: str):
    """Add Slack alert channel."""
    ssm = boto3.client('ssm')
    
    ssm.put_parameter(
        Name=f'/zerotrust/alerts/slack/{channel_name}',
        Value=webhook_url,
        Type='SecureString',
        Overwrite=True
    )
    
    print(f"Added Slack channel: {channel_name}")

def add_sns_subscription(topic_arn: str, endpoint: str, protocol: 'email' | 'sms' | 'lambda'):
    """Add SNS subscription."""
    sns = boto3.client('sns')
    
    response = sns.subscribe(
        TopicArn=topic_arn,
        Protocol=protocol,
        Endpoint=endpoint,
        ReturnSubscriptionArn=True
    )
    
    print(f"Subscribed {endpoint} to {topic_arn}")
    return response['SubscriptionArn']
```

---

## 4. Troubleshooting

### 4.1 Common Issues

| Issue | Symptom | Resolution |
|-------|---------|------------|
| Lambda timeout | Scan completes partially | Increase timeout or reduce batch size |
| Permission denied | Access denied errors | Verify IAM role permissions |
| No findings | Expected violations not detected | Check resource collection |
| Alert not received | Missing notifications | Verify SNS/Slack configuration |
| Slow scans | Long scan duration | Enable parallel scanning |

### 4.2 Debug Commands

```bash
# View Lambda logs
aws logs tail /aws/lambda/zerotrust-compliance-scanner --follow

# Check Lambda invocation errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/zerotrust-compliance-scanner \
  --filter-pattern "ERROR" \
  --start-time $(date -u -v-1h +%s)000

# Check DynamoDB scan errors
aws dynamodb describe-table \
  --table-name zerotrust-compliance-scan-results \
  --query 'Table'

# Check S3 bucket access
aws s3api list-objects \
  --bucket zerotrust-compliance-reports \
  --max-items 10

# Test SNS publish
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:123456789012:compliance-alerts \
  --message "Test alert from operations runbook"
```

### 4.3 Log Analysis

```python
# analyze_errors.py
import boto3

def analyze_error_logs(hours=24):
    """Analyze error patterns in logs."""
    logs = boto3.client('logs')
    
    response = logs.filter-log-events(
        logGroupName='/aws/lambda/zerotrust-compliance-scanner',
        startTime=(datetime.now() - timedelta(hours=hours)).timestamp() * 1000,
        filterPattern='ERROR'
    )
    
    error_counts = {}
    for event in response.get('events', []):
        message = event.get('message', '')
        # Extract error type
        if 'ClientError' in message:
            error_type = 'AWS API Error'
        elif 'ValidationError' in message:
            error_type = 'Validation Error'
        elif 'Timeout' in message:
            error_type = 'Timeout'
        else:
            error_type = 'Other'
        
        error_counts[error_type] = error_counts.get(error_type, 0) + 1
    
    # Print sorted results
    for error_type, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{error_type}: {count}")
    
    return error_counts
```

---

## 5. Incident Response

### 5.1 Severity Levels

| Level | Criteria | Response Time | Example |
|-------|----------|---------------|---------|
| **SEV-1** | Critical finding in production | 15 min | Data exposure |
| **SEV-2** | High finding in production | 1 hour | Misconfigured security group |
| **SEV-3** | Multiple medium findings | 4 hours | Policy violations |
| **SEV-4** | Single medium or low | 24 hours | Documentation issue |

### 5.2 Incident Runbook

```bash
#!/bin/bash
# incident_response.sh SEV_LEVEL RULE_ID RESOURCE_ID

SEV_LEVEL=$1
RULE_ID=$2
RESOURCE_ID=$3

echo "=== INCIDENT RESPONSE ==="
echo "Severity: $SEV_LEVEL"
echo "Rule: $RULE_ID"
echo "Resource: $RESOURCE_ID"
echo "Time: $(date)"
echo ""

# Step 1: Acknowledge
echo "1. ACKNOWLEDGE INCIDENT"
# Acknowledge in PagerDuty or incident management system

# Step 2: Assess
echo "2. ASSESS IMPACT"
# Determine if resource is in production
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].[InstanceId,Tags[?Key=='Name'].Value|[0],State.Name]" \
  --output table

# Step 3: Contain
echo "3. CONTAIN"
# If critical, contain the resource
# aws ec2 modify-instance-attribute --instance-id $RESOURCE_ID --no-source-dest-check

# Step 4: Notify
echo "4. NOTIFY STAKEHOLDERS"
# Send notification
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:123456789012:security-incidents \
  --message "INCIDENT $SEV_LEVEL: $RULE_ID on $RESOURCE_ID"

# Step 5: Document
echo "5. DOCUMENT"
# Create incident record in documentation system
```

---

## 6. Maintenance Tasks

### 6.1 Weekly Tasks

```bash
#!/bin/bash
# weekly_maintenance.sh

echo "=== Weekly Maintenance ==="
echo "Date: $(date)"
echo ""

# 1. Review rule effectiveness
echo "1. Reviewing rule effectiveness..."
# Check false positive rate

# 2. Clean up old data
echo "2. Cleaning up old data..."
aws s3 ls s3://zerotrust-compliance-reports/ | while read -r date; do
    if [ $(date -d "$date" +%s) -lt $(date -d "-30 days" +%s) ]; then
        echo "Deleting: $date"
        aws s3 rm s3://zerotrust-compliance-reports/$date --recursive
    fi
done

# 3. Rotate secrets
echo "3. Checking secret rotation..."
aws secretsmanager list-secrets \
  --filters "Key=tag-key,Values=zerotrust" \
  --query 'SecretList[].Name'

# 4. Review IAM roles
echo "4. Reviewing IAM roles..."
aws iam list-roles \
  --query 'Roles[?contains(RoleName, `zerotrust`)]'

# 5. Check cost optimization
echo "5. Checking cost..."
aws ce get-cost-and-usage \
  --time-period Start=$(date -d "-7 days" +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE
```

### 6.2 Monthly Tasks

```python
# monthly_report.py
def generate_monthly_compliance_report():
    """Generate monthly compliance summary report."""
    from datetime import datetime, timedelta
    import boto3
    
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('zerotrust-compliance-scan-results')
    
    # Get last 30 days
    start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    
    # Aggregate metrics
    metrics = {
        'total_scans': 0,
        'total_resources_scanned': 0,
        'total_findings': 0,
        'critical_findings': 0,
        'high_findings': 0,
        'remediated': 0,
        'providers': set(),
    }
    
    # Query all scans from last 30 days
    response = table.scan(
        FilterExpression="begins_with(#ts, :date)",
        ExpressionAttributeNames={'#ts': 'timestamp'},
        ExpressionAttributeValues={':date': start_date}
    )
    
    for item in response.get('Items', []):
        metrics['total_scans'] += 1
        metrics['total_resources_scanned'] += item.get('total_resources', 0)
        metrics['total_findings'] += item.get('findings_count', 0)
        metrics['critical_findings'] += item.get('summary', {}).get('critical', 0)
        metrics['high_findings'] += item.get('summary', {}).get('high', 0)
        metrics['providers'].add(item.get('provider', ''))
    
    # Generate report
    report = f"""
    Monthly Compliance Report
    =======================
    Period: {start_date} to {datetime.now().strftime('%Y-%m-%d')}
    
    Summary:
    - Total Scans: {metrics['total_scans']}
    - Resources Scanned: {metrics['total_resources_scanned']}
    - Total Findings: {metrics['total_findings']}
    - Critical: {metrics['critical_findings']}
    - High: {metrics['high_findings']}
    - Providers: {', '.join(metrics['providers'])}
    
    Compliance Score: {((metrics['total_resources_scanned'] - metrics['total_findings']) / max(metrics['total_resources_scanned'], 1) * 100):.1f}%
    """
    
    print(report)
    
    # Save to S3
    s3 = boto3.client('s3')
    s3.put_object(
        Bucket='zerotrust-compliance-reports',
        Key=f"monthly/compliance_report_{datetime.now().strftime('%Y-%m')}.txt",
        Body=report,
        ContentType='text/plain'
    )
```

---

## 7. Escalation

### 7.1 Escalation Matrix

| Level | Contact | Response Time | Examples |
|-------|---------|---------------|----------|
| **L1** | On-call engineer | 15 min | Lambda errors, failed scans |
| **L2** | Security team lead | 1 hour | Multiple critical findings |
| **L3** | CISO | 4 hours | Data breach, active attack |
| **L4** | Executive team | 24 hours | Major compliance violation |

### 7.2 Escalation Script

```bash
#!/bin/bash
# escalate.sh INCIDENT_TYPE SEVERITY DESCRIPTION

INCIDENT_TYPE=$1
SEVERITY=$2
DESCRIPTION=$3

# Determine escalation level
case $SEVERITY in
    CRITICAL)
        LEVEL=3
        CONTACT="security-lead@example.com"
        PAGERDUTY_ROUTING_KEY="routing-key-critical"
        ;;
    HIGH)
        LEVEL=2
        CONTACT="security-team@example.com"
        PAGERDUTY_ROUTING_KEY="routing-key-high"
        ;;
    *)
        LEVEL=1
        CONTACT="oncall@example.com"
        PAGERDUTY_ROUTING_KEY="routing-key-default"
        ;;
esac

echo "Escalating incident:"
echo "Type: $INCIDENT_TYPE"
echo "Severity: $SEVERITY"
echo "Level: $LEVEL"
echo "Contact: $CONTACT"

# Send to PagerDuty
curl -X POST https://events.pagerduty.com/v2/enqueue \
  -H 'Content-Type: application/json' \
  -d '{
    "routing_key": "'$PAGERDUTY_ROUTING_KEY'",
    "event_action": "trigger",
    "dedup_key": "incident-$(date +%s)",
    "payload": {
      "summary": "'$INCIDENT_TYPE' - '$DESCRIPTION'",
      "severity": "'$SEVERITY'",
      "source": "zerotrust-compliance-scanner"
    }
  }'

# Send email notification
echo "Subject: [ESCALATION L$LEVEL] $INCIDENT_TYPE
To: $CONTACT
Incident Type: $INCIDENT_TYPE
Severity: $SEVERITY
Description: $DESCRIPTION
Time: $(date)
" | sendmail $CONTACT
```

---

## 8. Useful Links

| Resource | URL |
|----------|-----|
| AWS Console | https://console.aws.amazon.com/ |
| CloudWatch | https://console.aws.amazon.com/cloudwatch/ |
| DynamoDB | https://console.aws.amazon.com/dynamodb/ |
| PagerDuty | https://app.pagerduty.com/ |
| GitHub Repo | https://github.com/org/zero-trust-compliance/ |

---

**Document Owner:** Security Team  
**Last Updated:** 2024-01-12  
**Next Review:** 2024-02-12

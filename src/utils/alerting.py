import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

try:
    from ..config import ScannerConfig, Finding, SeverityLevel
except ImportError:
    from core.config import ScannerConfig, Finding, SeverityLevel

logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.alert_channels = self._initialize_channels()

    def _initialize_channels(self) -> Dict[str, Any]:
        channels = {}

        if self.config.sns_topic_arn:
            channels["sns"] = self._create_sns_channel()

        if self.config.slack_webhook_url:
            channels["slack"] = self._create_slack_channel()

        if self.config.webhook_url:
            channels["webhook"] = self._create_webhook_channel()

        return channels

    def _create_sns_channel(self) -> Dict[str, Any]:
        return {
            "type": "sns",
            "topic_arn": self.config.sns_topic_arn,
        }

    def _create_slack_channel(self) -> Dict[str, Any]:
        return {
            "type": "slack",
            "webhook_url": self.config.slack_webhook_url,
        }

    def _create_webhook_channel(self) -> Dict[str, Any]:
        return {
            "type": "webhook",
            "url": self.config.webhook_url,
        }

    def send_alert(self, finding: Finding):
        if finding.severity not in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            return

        alert = self._format_finding_alert(finding)

        for channel_name, channel_config in self.alert_channels.items():
            try:
                if channel_config["type"] == "sns":
                    self._send_sns_alert(alert, channel_config)
                elif channel_config["type"] == "slack":
                    self._send_slack_alert(alert, channel_config)
                elif channel_config["type"] == "webhook":
                    self._send_webhook_alert(alert, channel_config)
            except Exception as e:
                logger.error(f"Error sending alert via {channel_name}: {e}")

    def send_batch_alert(self, findings: List[Finding]):
        critical_findings = [
            f for f in findings if f.severity == SeverityLevel.CRITICAL
        ]
        high_findings = [f for f in findings if f.severity == SeverityLevel.HIGH]

        if not critical_findings and not high_findings:
            return

        alert = {
            "alert_type": "BATCH_COMPLIANCE_ALERT",
            "timestamp": datetime.utcnow().isoformat(),
            "critical_count": len(critical_findings),
            "high_count": len(high_findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "resource_id": f.resource_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "remediation": f.remediation,
                }
                for f in (critical_findings[:10] + high_findings[:10])
            ],
        }

        for channel_name, channel_config in self.alert_channels.items():
            try:
                if channel_config["type"] == "sns":
                    self._send_sns_alert(alert, channel_config)
                elif channel_config["type"] == "slack":
                    self._send_slack_alert(alert, channel_config)
                elif channel_config["type"] == "webhook":
                    self._send_webhook_alert(alert, channel_config)
            except Exception as e:
                logger.error(f"Error sending batch alert via {channel_name}: {e}")

    def _format_finding_alert(self, finding: Finding) -> Dict[str, Any]:
        return {
            "alert_type": "COMPLIANCE_VIOLATION",
            "timestamp": datetime.utcnow().isoformat(),
            "finding": {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "resource_id": finding.resource_id,
                "resource_type": finding.resource_type,
                "resource_name": finding.resource_name,
                "severity": finding.severity.value,
                "message": finding.message,
                "remediation": finding.remediation,
                "provider": finding.cloud_provider.value,
                "region": finding.region,
                "account_id": finding.account_id,
                "evidence": finding.evidence,
            },
            "urgency": self._calculate_urgency(finding.severity),
        }

    def _calculate_urgency(self, severity: SeverityLevel) -> str:
        if severity == SeverityLevel.CRITICAL:
            return "P1 - Critical"
        elif severity == SeverityLevel.HIGH:
            return "P2 - High"
        elif severity == SeverityLevel.MEDIUM:
            return "P3 - Medium"
        else:
            return "P4 - Low"

    def _send_sns_alert(self, alert: Dict[str, Any], channel: Dict[str, Any]):
        import boto3

        sns = boto3.client("sns")

        message = json.dumps(alert, indent=2, default=str)

        subject = f"ALERT: {alert.get('urgency', 'Compliance Issue')} - {alert.get('finding', {}).get('rule_id', 'Unknown Rule')}"

        sns.publish(
            TopicArn=channel["topic_arn"],
            Message=message,
            Subject=subject[:100],
        )

        logger.info(f"SNS alert sent to {channel['topic_arn']}")

    def _send_slack_alert(self, alert: Dict[str, Any], channel: Dict[str, Any]):
        import requests

        finding = alert.get("finding", {})
        severity = finding.get("severity", "unknown")

        color_map = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
        }
        color = color_map.get(severity, "#6c757d")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"Compliance Alert: {finding.get('rule_id', 'Unknown')}",
                    "fields": [
                        {"title": "Severity", "value": severity.upper(), "short": True},
                        {
                            "title": "Resource",
                            "value": finding.get("resource_id", "Unknown"),
                            "short": True,
                        },
                        {
                            "title": "Resource Type",
                            "value": finding.get("resource_type", "Unknown"),
                            "short": True,
                        },
                        {
                            "title": "Provider",
                            "value": finding.get("provider", "Unknown"),
                            "short": True,
                        },
                        {
                            "title": "Message",
                            "value": finding.get("message", "No message")[:100],
                        },
                        {
                            "title": "Remediation",
                            "value": finding.get(
                                "remediation", "No remediation available"
                            )[:100],
                        },
                    ],
                    "footer": "Zero-Trust Compliance Scanner",
                    "ts": int(datetime.utcnow().timestamp()),
                }
            ]
        }

        requests.post(channel["webhook_url"], json=payload, timeout=30)
        logger.info(f"Slack alert sent")

    def _send_webhook_alert(self, alert: Dict[str, Any], channel: Dict[str, Any]):
        import requests

        try:
            response = requests.post(
                channel["url"],
                json=alert,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            response.raise_for_status()
            logger.info(f"Webhook alert sent to {channel['url']}")
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            raise

    def send_daily_digest(
        self, findings: List[Finding], date: Optional[datetime] = None
    ):
        date = date or datetime.utcnow()

        digest = {
            "digest_type": "DAILY_COMPLIANCE_DIGEST",
            "date": date.strftime("%Y-%m-%d"),
            "summary": {
                "total_findings": len(findings),
                "critical": len(
                    [f for f in findings if f.severity == SeverityLevel.CRITICAL]
                ),
                "high": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
                "medium": len(
                    [f for f in findings if f.severity == SeverityLevel.MEDIUM]
                ),
                "low": len([f for f in findings if f.severity == SeverityLevel.LOW]),
            },
            "by_rule": self._group_findings_by_rule(findings),
            "by_resource": self._group_findings_by_resource(findings),
            "top_remediations": self._get_top_remediations(findings),
        }

        for channel_name, channel_config in self.alert_channels.items():
            if channel_config["type"] == "sns":
                self._send_sns_alert(digest, channel_config)

    def _group_findings_by_rule(self, findings: List[Finding]) -> Dict[str, int]:
        from collections import Counter

        return dict(Counter(f.rule_id for f in findings))

    def _group_findings_by_resource(self, findings: List[Finding]) -> Dict[str, int]:
        from collections import Counter

        return dict(Counter(f.resource_type for f in findings))

    def _get_top_remediations(
        self, findings: List[Finding], limit: int = 5
    ) -> List[Dict[str, str]]:
        seen = set()
        remediations = []

        for finding in findings:
            key = finding.rule_id
            if key not in seen and finding.severity in [
                SeverityLevel.CRITICAL,
                SeverityLevel.HIGH,
            ]:
                seen.add(key)
                remediations.append(
                    {
                        "rule_id": finding.rule_id,
                        "remediation": finding.remediation,
                        "severity": finding.severity.value,
                    }
                )

            if len(remediations) >= limit:
                break

        return remediations


class PagerDutyIntegration:
    def __init__(self, api_key: str, service_id: str):
        self.api_key = api_key
        self.service_id = service_id
        self.base_url = "https://api.pagerduty.com"

    def trigger_incident(self, finding: Finding, routing_key: str):
        import requests

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": f"compliance-{finding.finding_id}",
            "payload": {
                "summary": f"Compliance Violation: {finding.rule_id}",
                "severity": self._map_severity(finding.severity),
                "source": "zero-trust-compliance-scanner",
                "custom_details": {
                    "rule_id": finding.rule_id,
                    "resource_id": finding.resource_id,
                    "resource_type": finding.resource_type,
                    "message": finding.message,
                    "remediation": finding.remediation,
                },
            },
        }

        try:
            response = requests.post(
                f"{self.base_url}/events",
                json=payload,
                headers={"Authorization": f"Token token={self.api_key}"},
                timeout=30,
            )
            response.raise_for_status()
            logger.info(f"PagerDuty incident triggered for {finding.rule_id}")
        except Exception as e:
            logger.error(f"Error triggering PagerDuty incident: {e}")

    def _map_severity(self, severity: SeverityLevel) -> str:
        mapping = {
            SeverityLevel.CRITICAL: "critical",
            SeverityLevel.HIGH: "error",
            SeverityLevel.MEDIUM: "warning",
            SeverityLevel.LOW: "info",
            SeverityLevel.INFO: "info",
        }
        return mapping.get(severity, "info")


class SecurityHubIntegration:
    def __init__(self, region: str = "us-east-1"):
        self.region = region

    def import_findings(self, findings: List[Finding], aws_account_id: str):
        import boto3

        securityhub = boto3.client("securityhub", region_name=self.region)

        findings_to_import = []

        for finding in findings:
            if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                securityhub_finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": finding.finding_id,
                    "ProductArn": f"arn:aws:securityhub:{self.region}:{aws_account_id}:product/{aws_account_id}/default",
                    "GeneratorId": finding.rule_id,
                    "AwsAccountId": aws_account_id,
                    "Types": ["Software and Configuration Checks/Industry Compliance"],
                    "CreatedAt": finding.timestamp.isoformat(),
                    "UpdatedAt": datetime.utcnow().isoformat(),
                    "Severity": {
                        "Label": finding.severity.value.upper(),
                        "Normalized": self._get_severity_normalized(finding.severity),
                    },
                    "Title": f"Compliance Violation: {finding.rule_id}",
                    "Description": finding.message,
                    "Remediation": {
                        "Recommendation": {
                            "Text": finding.remediation,
                            "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
                        }
                    },
                    "Resources": [
                        {
                            "Type": self._map_resource_type(finding.resource_type),
                            "Id": finding.resource_id,
                            "Partition": "aws",
                            "Region": finding.region or self.region,
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": ["CIS AWS Foundations Benchmark"],
                    },
                }
                findings_to_import.append(securityhub_finding)

        if findings_to_import:
            try:
                securityhub.batch_import_findings(Findings=findings_to_import)
                logger.info(
                    f"Imported {len(findings_to_import)} findings to Security Hub"
                )
            except Exception as e:
                logger.error(f"Error importing findings to Security Hub: {e}")

    def _get_severity_normalized(self, severity: SeverityLevel) -> int:
        mapping = {
            SeverityLevel.CRITICAL: 90,
            SeverityLevel.HIGH: 70,
            SeverityLevel.MEDIUM: 50,
            SeverityLevel.LOW: 30,
            SeverityLevel.INFO: 0,
        }
        return mapping.get(severity, 0)

    def _map_resource_type(self, resource_type: str) -> str:
        if "S3" in resource_type:
            return "AwsS3Bucket"
        elif "EC2" in resource_type or "Instance" in resource_type:
            return "AwsEc2Instance"
        elif "IAM" in resource_type:
            return "AwsIamRole"
        elif "RDS" in resource_type:
            return "AwsRdsDbInstance"
        elif "KMS" in resource_type:
            return "AwsKmsKey"
        else:
            return "Other"

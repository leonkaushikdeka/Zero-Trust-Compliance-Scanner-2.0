import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

try:
    from ..config import ScannerConfig, ScanResult, CloudProvider, SeverityLevel
except ImportError:
    from core.config import ScannerConfig, ScanResult, CloudProvider, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class ComplianceReport:
    report_id: str
    generated_at: datetime
    scan_period: Dict[str, str]
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    recommendations: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "scan_period": self.scan_period,
            "summary": self.summary,
            "findings": self.findings,
            "recommendations": self.recommendations,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_html(self) -> str:
        return self._generate_html_report()

    def _generate_html_report(self) -> str:
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }

        findings_html = ""
        for finding in self.findings[:50]:
            color = severity_colors.get(finding.get("severity", "info"), "#6c757d")
            findings_html += f"""
            <tr style="border-bottom: 1px solid #dee2e6;">
                <td style="padding: 12px;">
                    <span style="background-color: {color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px;">
                        {finding.get("severity", "").upper()}
                    </span>
                </td>
                <td style="padding: 12px;">{finding.get("rule_id", "")}</td>
                <td style="padding: 12px;">{finding.get("resource_id", "")}</td>
                <td style="padding: 12px;">{finding.get("message", "")}</td>
                <td style="padding: 12px;">{finding.get("remediation", "")}</td>
            </tr>
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Zero-Trust Compliance Report</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
                .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
                .summary-card h3 {{ margin: 0; font-size: 36px; color: #333; }}
                .summary-card p {{ margin: 5px 0 0 0; color: #666; }}
                .score-card {{ background: {"#28a745" if self.summary.get("overall_score", 100) >= 80 else "#ffc107" if self.summary.get("overall_score", 100) >= 60 else "#dc3545"}; color: white; }}
                .score-card h3 {{ color: white; }}
                .findings-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                .findings-table th {{ background: #343a40; color: white; padding: 12px; text-align: left; }}
                .recommendations {{ padding: 30px; background: #f8f9fa; }}
                .recommendation {{ background: white; padding: 15px; margin-bottom: 10px; border-radius: 4px; border-left: 4px solid #007bff; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Zero-Trust Compliance Report</h1>
                    <p>Report ID: {self.report_id}</p>
                    <p>Generated: {self.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                </div>
                
                <div class="summary">
                    <div class="summary-card score-card">
                        <h3>{self.summary.get("overall_score", 100)}%</h3>
                        <p>Compliance Score</p>
                    </div>
                    <div class="summary-card">
                        <h3>{self.summary.get("total_resources_scanned", 0)}</h3>
                        <p>Resources Scanned</p>
                    </div>
                    <div class="summary-card">
                        <h3>{self.summary.get("total_findings", 0)}</h3>
                        <p>Total Findings</p>
                    </div>
                    <div class="summary-card" style="border-left: 4px solid #dc3545;">
                        <h3>{self.summary.get("critical_findings", []) and len(self.summary.get("critical_findings", [])) or 0}</h3>
                        <p>Critical Issues</p>
                    </div>
                </div>
                
                <div style="padding: 0 30px;">
                    <h2>Findings ({len(self.findings)})</h2>
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Rule ID</th>
                                <th>Resource</th>
                                <th>Message</th>
                                <th>Remediation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {findings_html}
                        </tbody>
                    </table>
                </div>
                
                <div class="recommendations">
                    <h2>Recommendations</h2>
                    {"".join(f'<div class="recommendation"><strong>{r.get("rule_id", "")}:</strong> {r.get("recommendation", "")}</div>' for r in self.recommendations[:10])}
                </div>
            </div>
        </body>
        </html>
        """
        return html


class ReportGenerator:
    def __init__(self, config: ScannerConfig):
        self.config = config

    def generate_report(
        self,
        results: Dict[CloudProvider, ScanResult],
        scan_start: datetime,
        scan_end: datetime,
    ) -> ComplianceReport:
        all_findings = []
        total_resources = 0
        total_findings = 0

        for provider, result in results.items():
            if not result:
                continue

            total_resources += result.total_resources
            total_findings += result.summary["total_findings"]

            for finding in result.findings:
                all_findings.append(
                    {
                        "rule_id": finding.rule_id,
                        "severity": finding.severity.value,
                        "resource_id": finding.resource_id,
                        "resource_type": finding.resource_type,
                        "message": finding.message,
                        "remediation": finding.remediation,
                        "provider": finding.cloud_provider.value,
                        "region": finding.region,
                        "timestamp": finding.timestamp.isoformat(),
                    }
                )

        all_findings.sort(
            key=lambda x: (
                ["critical", "high", "medium", "low", "info"].index(
                    x.get("severity", "info")
                ),
                x.get("rule_id", ""),
            )
        )

        recommendations = self._generate_recommendations(all_findings)

        score = 0
        if total_resources > 0:
            score = (total_resources - total_findings) / total_resources * 100

        report = ComplianceReport(
            report_id=f"report-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.utcnow(),
            scan_period={
                "start": scan_start.isoformat(),
                "end": scan_end.isoformat(),
            },
            summary={
                "overall_score": round(score, 2),
                "total_resources_scanned": total_resources,
                "total_findings": total_findings,
                "by_severity": {
                    "critical": len(
                        [f for f in all_findings if f.get("severity") == "critical"]
                    ),
                    "high": len(
                        [f for f in all_findings if f.get("severity") == "high"]
                    ),
                    "medium": len(
                        [f for f in all_findings if f.get("severity") == "medium"]
                    ),
                    "low": len([f for f in all_findings if f.get("severity") == "low"]),
                },
                "by_provider": {
                    provider.value: {
                        "resources": result.total_resources if result else 0,
                        "findings": result.summary["total_findings"] if result else 0,
                    }
                    for provider, result in results.items()
                    if result
                },
                "critical_findings": all_findings[:10],
            },
            findings=all_findings,
            recommendations=recommendations,
        )

        return report

    def _generate_recommendations(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        recommendations = []
        seen_rules = set()

        for finding in findings:
            rule_id = finding.get("rule_id", "")
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            if finding.get("severity") in ["critical", "high"]:
                recommendations.append(
                    {
                        "rule_id": rule_id,
                        "recommendation": finding.get(
                            "remediation", "Review and remediate this compliance issue."
                        ),
                    }
                )

        return recommendations[:20]

    def save_report_to_s3(
        self, results: Dict[CloudProvider, ScanResult], bucket: str, key: str
    ):
        import boto3

        scan_start = datetime.utcnow()
        report = self.generate_report(results, scan_start, datetime.utcnow())

        s3 = boto3.client("s3")

        try:
            s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=report.to_json(),
                ContentType="application/json",
                ServerSideEncryption="aws:kms",
            )
            logger.info(f"Saved report to s3://{bucket}/{key}")

            html_key = key.replace(".json", ".html")
            s3.put_object(
                Bucket=bucket,
                Key=html_key,
                Body=report.to_html(),
                ContentType="text/html",
                ServerSideEncryption="aws:kms",
            )
            logger.info(f"Saved HTML report to s3://{bucket}/{html_key}")

        except Exception as e:
            logger.error(f"Error saving report to S3: {e}")
            raise

    def save_to_s3(self, result: ScanResult, bucket: str):
        try:
            import boto3

            scan_data = {
                "scan_id": result.scan_id,
                "timestamp": result.timestamp.isoformat(),
                "provider": result.cloud_provider.value
                if hasattr(result.cloud_provider, "value")
                else str(result.cloud_provider),
                "summary": result.summary,
                "findings_count": len(result.findings),
                "duration_seconds": result.duration_seconds,
                "rules_applied": result.rules_applied,
            }

            key = f"results/{result.cloud_provider.value if hasattr(result.cloud_provider, 'value') else str(result.cloud_provider)}/{result.scan_id}.json"

            s3 = boto3.client("s3")
            s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=json.dumps(scan_data, indent=2, default=str),
                ContentType="application/json",
                ServerSideEncryption="aws:kms",
            )
            logger.info(f"Saved scan result to s3://{bucket}/{key}")

        except ImportError:
            logger.warning("boto3 not installed, skipping S3 save")
        except Exception as e:
            logger.error(f"Error saving to S3: {e}")

    def send_webhook_report(
        self, result: ScanResult, webhook_url: str, scan_id: Optional[str] = None
    ):
        import requests

        payload = {
            "scan_id": scan_id or result.scan_id,
            "timestamp": result.timestamp.isoformat(),
            "provider": result.cloud_provider.value,
            "summary": result.summary,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "resource_id": f.resource_id,
                    "message": f.message,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ],
            "compliance_score": self._calculate_score(result),
        }

        try:
            response = requests.post(webhook_url, json=payload, timeout=30)
            response.raise_for_status()
            logger.info(f"Webhook report sent successfully to {webhook_url}")
        except Exception as e:
            logger.error(f"Error sending webhook report: {e}")
            raise

    def send_slack_alert(self, result: ScanResult, webhook_url: str):
        import requests

        critical_count = result.summary.get("critical", 0)
        high_count = result.summary.get("high", 0)

        color = (
            "good"
            if critical_count == 0 and high_count == 0
            else "warning"
            if high_count > 0
            else "danger"
        )

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Zero-Trust Compliance Scan Results",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Provider:*\n{result.cloud_provider.value}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Findings:*\n{result.summary['total_findings']}",
                    },
                    {"type": "mrkdwn", "text": f"*Critical:*\n{critical_count}"},
                    {"type": "mrkdwn", "text": f"*High:*\n{high_count}"},
                ],
            },
        ]

        if result.findings[:5]:
            findings_text = "\n".join(
                [
                    f"• *{f.rule_id}*: {f.resource_id} - {f.message[:100]}..."
                    for f in result.findings[:5]
                ]
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Top Findings:*\n{findings_text}",
                    },
                }
            )

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                }
            ]
        }

        try:
            response = requests.post(webhook_url, json=payload, timeout=30)
            response.raise_for_status()
            logger.info(f"Slack alert sent successfully")
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")

    def _calculate_score(self, result: ScanResult) -> float:
        if result.total_resources == 0:
            return 100.0

        penalty = (
            result.summary.get("critical", 0) * 25
            + result.summary.get("high", 0) * 10
            + result.summary.get("medium", 0) * 5
            + result.summary.get("low", 0) * 1
        )

        max_penalty = result.total_resources * 25
        return max(0, 100 - (penalty / max_penalty * 100))

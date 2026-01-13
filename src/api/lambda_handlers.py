import json
import logging
import os
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional

from ..config import ScannerConfig, CloudProvider, SeverityLevel, ConfigManager
from ..scanners.compliance_scanner import ComplianceScanner
from ..utils.reporting import ReportGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_config_from_s3(
    s3_bucket: str, config_key: str = "config/scanner_config.json"
) -> ScannerConfig:
    import boto3

    s3 = boto3.client("s3")

    try:
        response = s3.get_object(Bucket=s3_bucket, Key=config_key)
        config_data = json.loads(response["Body"].read().decode())

        config = ScannerConfig(
            enabled_providers=[
                CloudProvider(p) for p in config_data.get("enabled_providers", [])
            ],
            aws_regions=config_data.get("aws_regions", ["us-east-1"]),
            severity_threshold=SeverityLevel(
                config_data.get("severity_threshold", "low")
            ),
            batch_size=config_data.get("batch_size", 100),
            timeout_seconds=config_data.get("timeout_seconds", 300),
            parallel_scans=config_data.get("parallel_scans", 10),
            enable_real_time=config_data.get("enable_real_time", False),
            webhook_url=config_data.get("webhook_url"),
            sns_topic_arn=config_data.get("sns_topic_arn"),
            slack_webhook_url=config_data.get("slack_webhook_url"),
            s3_bucket=config_data.get("s3_bucket"),
            dynamodb_table=config_data.get("dynamodb_table"),
            dry_run=config_data.get("dry_run", False),
            verbose=config_data.get("verbose", True),
        )
        return config
    except Exception as e:
        logger.error(f"Error loading config from S3: {e}")
        return ScannerConfig()


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    scan_id = f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hashlib.md5(str(context.invoked_function_arn).encode()).hexdigest()[:8]}"

    logger.info(f"Starting compliance scan: {scan_id}")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    try:
        config_bucket = os.environ.get("CONFIG_S3_BUCKET")
        if config_bucket:
            config = load_config_from_s3(config_bucket)
        else:
            config = ScannerConfig()

        scanner = ComplianceScanner(config)

        scan_type = event.get("scan_type", "full")
        providers = event.get("providers", None)
        rule_ids = event.get("rule_ids", None)

        if scan_type == "incremental":
            change_events = event.get("changes", [])
            providers_list = [
                CloudProvider(p)
                for p in (providers or [p.value for p in config.enabled_providers])
            ]
            results = scanner.run_incremental_scan(
                providers_list, change_events, rule_ids
            )
        else:
            if providers:
                providers_list = [CloudProvider(p) for p in providers]
            else:
                providers_list = None
            results = scanner.run_scan(providers_list, rule_ids)

        summary = scanner.get_compliance_summary(results)

        if not config.dry_run and config.s3_bucket:
            report_generator = ReportGenerator(config)
            report_key = f"reports/{scan_id}/scan_result.json"
            report_generator.save_report_to_s3(results, config.s3_bucket, report_key)

        if summary.get("critical_findings"):
            send_critical_alerts(summary["critical_findings"], config)

        formatted_results = {}
        for provider, result in results.items():
            provider_key = (
                provider.value if hasattr(provider, "value") else str(provider)
            )
            formatted_results[provider_key] = {
                "total_resources": result.total_resources if result else 0,
                "findings_count": len(result.findings) if result else 0,
                "score": scanner._calculate_score(result) if result else 100,
            }

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "scan_id": scan_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "summary": summary,
                    "results": formatted_results,
                },
                default=str,
            ),
        }

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e), "scan_id": scan_id}),
        }


def scheduled_scan_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    logger.info("Starting scheduled compliance scan")

    config = ScannerConfig(
        enabled_providers=[
            CloudProvider.AWS,
            CloudProvider.AZURE,
            CloudProvider.GCP,
        ],
        aws_regions=["us-east-1", "us-west-2", "eu-west-1"],
        enable_real_time=True,
        verbose=True,
    )

    scanner = ComplianceScanner(config)
    results = scanner.run_scan()

    summary = scanner.get_compliance_summary(results)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "scan_type": "scheduled",
                "summary": summary,
                "timestamp": datetime.utcnow().isoformat(),
            },
            default=str,
        ),
    }


def ci_cd_scan_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    scan_id = f"cicd-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    commit_sha = event.get("commit_sha", "unknown")
    pipeline_id = event.get("pipeline_id", "unknown")
    provider_value = event.get("provider", "aws")

    try:
        provider = CloudProvider(provider_value)
    except ValueError:
        provider = CloudProvider.AWS

    logger.info(f"Running CI/CD scan for commit {commit_sha}")

    config = ScannerConfig(
        enabled_providers=[provider],
        aws_regions=["us-east-1"],
        dry_run=False,
        verbose=True,
    )

    scanner = ComplianceScanner(config)
    report = scanner.run_ci_cd_scan(provider, commit_sha, pipeline_id)

    report["status"] = "pass" if report.get("pass") else "fail"

    if not report.get("pass"):
        report["block_deployment"] = report.get("compliance_score", 100) < 80

        if report.get("compliance_score", 100) < 70:
            logger.error(
                f"Compliance scan FAILED: {report.get('failure_reason', 'Unknown')}"
            )
        else:
            logger.warning(
                f"Compliance scan passed with warnings: {report.get('failure_reason', 'Unknown')}"
            )

    return {"statusCode": 200, "body": json.dumps(report, default=str)}


def terraform_scan_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    scan_id = f"tf-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    plan_bucket = event.get("plan_s3_bucket")
    plan_key = event.get("plan_s3_key")
    repository = event.get("repository", "unknown")
    branch = event.get("branch", "unknown")

    logger.info(f"Scanning Terraform plan: s3://{plan_bucket}/{plan_key}")

    import boto3

    s3 = boto3.client("s3")
    response = s3.get_object(Bucket=plan_bucket, Key=plan_key)
    plan_json = json.loads(response["Body"].read().decode())

    config = ScannerConfig(
        enabled_providers=[CloudProvider.TERRAFORM],
        dry_run=False,
        verbose=True,
    )

    scanner = ComplianceScanner(config)
    result = scanner.scan_terraform_plan(plan_json)

    report = {
        "scan_id": scan_id,
        "timestamp": datetime.utcnow().isoformat(),
        "repository": repository,
        "branch": branch,
        "plan_key": plan_key,
        "total_resources": result.total_resources,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value
                if hasattr(f.severity, "value")
                else str(f.severity),
                "message": f.message,
                "remediation": f.remediation,
                "resource": f.resource_id,
            }
            for f in result.findings
        ],
        "pass": len(
            [
                f
                for f in result.findings
                if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            ]
        )
        == 0,
        "compliance_score": scanner._calculate_score(result),
    }

    if report["findings"]:
        report["findings_summary"] = {
            "critical": len(
                [f for f in result.findings if f.severity == SeverityLevel.CRITICAL]
            ),
            "high": len(
                [f for f in result.findings if f.severity == SeverityLevel.HIGH]
            ),
            "medium": len(
                [f for f in result.findings if f.severity == SeverityLevel.MEDIUM]
            ),
            "low": len([f for f in result.findings if f.severity == SeverityLevel.LOW]),
        }

    return {"statusCode": 200, "body": json.dumps(report, default=str)}


def send_critical_alerts(findings: list, config: ScannerConfig):
    if not findings:
        return

    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN") or config.sns_topic_arn
    if not sns_topic_arn:
        logger.warning("No SNS topic configured for critical alerts")
        return

    import boto3

    sns = boto3.client("sns")

    message = {
        "alert_type": "CRITICAL_COMPLIANCE_FINDINGS",
        "timestamp": datetime.utcnow().isoformat(),
        "findings_count": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id if hasattr(f, "rule_id") else str(f),
                "resource": f.resource_id if hasattr(f, "resource_id") else "unknown",
                "message": f.message if hasattr(f, "message") else "Unknown finding",
            }
            for f in findings[:10]
        ],
    }

    try:
        sns.publish(
            TopicArn=sns_topic_arn,
            Message=json.dumps(message, default=str),
            Subject="CRITICAL: Zero-Trust Compliance Violations Detected",
        )
        logger.info(f"Sent critical alert for {len(findings)} findings")
    except Exception as e:
        logger.error(f"Failed to send critical alert: {e}")


class CloudWatchEventHandler:
    @staticmethod
    def handle_config_rule_compliance_change(event: Dict[str, Any], context):
        logger.info(f"Received Config rule change: {json.dumps(event)}")

        detail = event.get("detail", {})
        new_eval = detail.get("newEvaluationResult", {})
        compliance_type = new_eval.get("complianceType", "")

        if compliance_type == "NON_COMPLIANT":
            resource_id = detail.get("resourceId")
            config_rule_name = detail.get("configRuleName")

            scanner = ComplianceScanner()
            finding = {
                "resource_id": resource_id,
                "rule": config_rule_name,
                "message": f"Resource {resource_id} is non-compliant with {config_rule_name}",
                "timestamp": datetime.utcnow().isoformat(),
            }

            return {
                "statusCode": 200,
                "body": json.dumps({"processed": True, "finding": finding}),
            }

        return {"statusCode": 200, "body": json.dumps({"processed": False})}

    @staticmethod
    def handle_security_hub_finding(event: Dict[str, Any], context):
        logger.info(f"Received Security Hub finding: {json.dumps(event)}")

        findings = event.get("detail", {}).get("findings", [{}])
        finding = findings[0] if findings else {}

        severity_label = finding.get("Severity", {}).get("Label", "INFO")

        if severity_label in ["CRITICAL", "HIGH"]:
            scanner = ComplianceScanner()
            alert = {
                "source": "security_hub",
                "finding_id": finding.get("Id"),
                "title": finding.get("Title"),
                "severity": severity_label,
                "resource": finding.get("Resources", [{}])[0].get("Id", "unknown"),
            }

            logger.warning(f"Security Hub finding: {alert}")

        return {"statusCode": 200, "body": json.dumps({"processed": True})}

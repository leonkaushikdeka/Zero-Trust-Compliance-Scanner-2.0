"""
Health Check and Metrics Module for Zero-Trust Compliance Scanner.

Provides health check endpoints, CloudWatch metrics, and operational monitoring.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .config import CloudProvider

logger = logging.getLogger(__name__)


class HealthCheck:
    """Health check manager for compliance scanner components."""

    def __init__(
        self,
        dynamodb_table: Optional[str] = None,
        s3_bucket: Optional[str] = None,
    ):
        self.dynamodb_table = dynamodb_table
        self.s3_bucket = s3_bucket
        self.start_time = time.time()
        self.version = "1.0.0"

    def check_all(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check.

        Returns:
            Dict containing health status of all components.
        """
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": self.version,
            "uptime_seconds": self.get_uptime(),
            "components": {
                "rule_engine": self.check_rule_engine(),
                "aws_connector": self.check_aws_connection(),
                "storage": self.check_storage(),
            },
        }

    def check_rule_engine(self) -> Dict[str, Any]:
        """Check rule engine health."""
        try:
            from .rule_engine import RuleEngine

            engine = RuleEngine()
            rule_count = len(engine.rules)

            return {
                "status": "healthy" if rule_count > 0 else "unhealthy",
                "rules_loaded": rule_count,
                "providers": list(
                    set(r.cloud_provider.value for r in engine.rules.values())
                ),
            }
        except Exception as e:
            logger.error(f"Rule engine health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
            }

    def check_aws_connection(self) -> Dict[str, Any]:
        """Check AWS connection health."""
        try:
            import boto3

            sts = boto3.client("sts")
            identity = sts.get_caller_identity()

            return {
                "status": "healthy",
                "account_id": identity.get("Account", "unknown"),
                "user_arn": identity.get("Arn", "unknown"),
            }
        except Exception as e:
            logger.warning(f"AWS connection check failed: {e}")
            return {
                "status": "degraded",
                "error": str(e),
            }

    def check_storage(self) -> Dict[str, Any]:
        """Check storage health."""
        try:
            if self.dynamodb_table:
                import boto3

                dynamodb = boto3.resource("dynamodb")
                table = dynamodb.Table(self.dynamodb_table)
                table.load()

                return {
                    "status": "healthy",
                    "dynamodb_table": self.dynamodb_table,
                    "item_count": table.item_count
                    if hasattr(table, "item_count")
                    else "unknown",
                }

            return {
                "status": "healthy",
                "note": "No DynamoDB table configured",
            }
        except Exception as e:
            logger.error(f"Storage health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
            }

    def get_uptime(self) -> float:
        """Get scanner uptime in seconds."""
        return time.time() - self.start_time

    def to_json(self) -> str:
        """Serialize health check to JSON."""
        return json.dumps(self.check_all(), indent=2, default=str)


class MetricsCollector:
    """CloudWatch metrics collector for compliance scanner."""

    NAMESPACE = "ZeroTrustComplianceScanner"

    def __init__(self):
        self.metrics = []

    def emit_scan_started(
        self,
        provider: CloudProvider,
        resource_count: int,
    ) -> None:
        """Emit scan started metric."""
        self._put_metric(
            metric_name="ScanStarted",
            value=1,
            unit="Count",
            dimensions={
                "Provider": provider.value,
            },
        )

    def emit_scan_completed(
        self,
        provider: CloudProvider,
        duration_seconds: float,
        findings_count: int,
        compliance_score: float,
    ) -> None:
        """Emit scan completed metric."""
        self._put_metric(
            metric_name="ScanCompleted",
            value=1,
            unit="Count",
            dimensions={"Provider": provider.value},
        )
        self._put_metric(
            metric_name="ScanDuration",
            value=duration_seconds,
            unit="Seconds",
            dimensions={"Provider": provider.value},
        )
        self._put_metric(
            metric_name="FindingsCount",
            value=findings_count,
            unit="Count",
            dimensions={"Provider": provider.value},
        )
        self._put_metric(
            metric_name="ComplianceScore",
            value=compliance_score,
            unit="Percent",
            dimensions={"Provider": provider.value},
        )

    def emit_finding(
        self,
        provider: CloudProvider,
        severity: str,
        rule_id: str,
    ) -> None:
        """Emit finding detected metric."""
        self._put_metric(
            metric_name="FindingDetected",
            value=1,
            unit="Count",
            dimensions={
                "Provider": provider.value,
                "Severity": severity,
                "RuleId": rule_id,
            },
        )

    def emit_alert_sent(
        self,
        channel: str,
        severity: str,
    ) -> None:
        """Emit alert sent metric."""
        self._put_metric(
            metric_name="AlertSent",
            value=1,
            unit="Count",
            dimensions={
                "Channel": channel,
                "Severity": severity,
            },
        )

    def _put_metric(
        self,
        metric_name: str,
        value: float,
        unit: str,
        dimensions: Dict[str, str],
    ) -> None:
        """Put metric to CloudWatch."""
        try:
            import boto3

            cloudwatch = boto3.client("cloudwatch")
            cloudwatch.put_metric_data(
                Namespace=self.NAMESPACE,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Value": value,
                        "Unit": unit,
                        "Dimensions": [
                            {"Name": k, "Value": v} for k, v in dimensions.items()
                        ],
                        "Timestamp": datetime.now(timezone.utc),
                    },
                ],
            )
        except ImportError:
            logger.debug("boto3 not available, skipping metric")
        except Exception as e:
            logger.warning(f"Failed to emit metric {metric_name}: {e}")


class MetricsEndpoint:
    """Lambda function for metrics endpoint."""

    @staticmethod
    def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
        """Handle metrics request."""
        health = HealthCheck()
        metrics = MetricsCollector()

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps(
                {
                    "health": health.check_all(),
                    "metrics": {
                        "namespace": MetricsCollector.NAMESPACE,
                    },
                },
                indent=2,
                default=str,
            ),
        }


class HealthEndpoint:
    """Lambda function for health check endpoint."""

    @staticmethod
    def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
        """Handle health check request."""
        health = HealthCheck()
        health_status = health.check_all()

        status_code = 200 if health_status["status"] == "healthy" else 503

        return {
            "statusCode": status_code,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": health_status.to_json()
            if hasattr(health_status, "to_json")
            else json.dumps(health_status, indent=2, default=str),
        }


class ReadinessEndpoint:
    """Lambda function for Kubernetes readiness probe."""

    @staticmethod
    def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
        """Handle readiness probe."""
        health = HealthCheck()
        status = health.check_all()

        # Check if all critical components are healthy
        all_healthy = all(
            comp.get("status") == "healthy"
            for comp in status.get("components", {}).values()
        )

        return {
            "statusCode": 200 if all_healthy else 503,
            "headers": {
                "Content-Type": "application/json",
            },
            "body": json.dumps(
                {
                    "ready": all_healthy,
                    "checks": {
                        name: comp.get("status")
                        for name, comp in status.get("components", {}).items()
                    },
                }
            ),
        }


class LivenessEndpoint:
    """Lambda function for Kubernetes liveness probe."""

    @staticmethod
    def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
        """Handle liveness probe."""
        uptime = time.time() - time.time()  # Simple check

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
            },
            "body": json.dumps(
                {
                    "alive": True,
                    "uptime_seconds": uptime,
                }
            ),
        }

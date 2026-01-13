import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import uuid

try:
    from ..config import (
        ScannerConfig,
        CloudProvider,
        SeverityLevel,
        ComplianceStatus,
        ScanResult,
        Finding,
    )
    from ..rule_engine import RuleEngine
    from ..collectors.resource_collectors import ResourceCollector
    from ..utils.reporting import ReportGenerator
    from ..utils.alerting import AlertManager
except ImportError:
    from core.config import (
        ScannerConfig,
        CloudProvider,
        SeverityLevel,
        ComplianceStatus,
        ScanResult,
        Finding,
    )
    from core.rule_engine import RuleEngine
    from collectors.resource_collectors import ResourceCollector
    from utils.reporting import ReportGenerator
    from utils.alerting import AlertManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComplianceScanner:
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.rule_engine = RuleEngine()
        self.resource_collector = ResourceCollector(self.config)
        self.report_generator = ReportGenerator(self.config)
        self.alert_manager = AlertManager(self.config)

    def run_scan(
        self,
        providers: Optional[List[CloudProvider]] = None,
        rule_ids: Optional[List[str]] = None,
        resource_filter: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, ScanResult]:
        providers = providers or self.config.enabled_providers
        results = {}

        with ThreadPoolExecutor(max_workers=self.config.parallel_scans) as executor:
            futures = {}

            for provider in providers:
                future = executor.submit(
                    self._scan_provider, provider, rule_ids, resource_filter
                )
                futures[future] = provider

            for future in as_completed(futures):
                provider = futures[future]
                try:
                    result = future.result()
                    results[provider] = result

                    if result and result.findings:
                        self._handle_findings(result)

                    if not self.config.dry_run and result:
                        self._save_result(result)

                except Exception as e:
                    logger.error(f"Error scanning provider {provider}: {e}")
                    results[provider] = None

        return results

    def run_incremental_scan(
        self,
        providers: List[CloudProvider],
        change_events: List[Dict[str, Any]],
        rule_ids: Optional[List[str]] = None,
    ) -> Dict[str, ScanResult]:
        results = {}

        resource_changes = self._parse_change_events(change_events)

        for provider in providers:
            try:
                affected_resources = self._get_affected_resources(
                    provider, resource_changes
                )

                if affected_resources:
                    result = self.rule_engine.scan_resources(
                        affected_resources, provider, rule_ids
                    )
                    results[provider] = result

                    if result.findings:
                        self._handle_findings(result)

                    if not self.config.dry_run:
                        self._save_result(result)
                else:
                    results[provider] = None

            except Exception as e:
                logger.error(f"Error in incremental scan for {provider}: {e}")
                results[provider] = None

        return results

    def _parse_change_events(
        self, change_events: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        resource_changes = {}

        for event in change_events:
            resource_type = event.get("resource_type", "")
            resource_id = event.get("resource_id", "")

            if resource_type not in resource_changes:
                resource_changes[resource_type] = []

            if resource_id:
                resource_changes[resource_type].append(resource_id)

        return resource_changes

    def _get_affected_resources(
        self,
        provider: CloudProvider,
        resource_changes: Dict[str, List[str]],
    ) -> List[Dict[str, Any]]:
        all_resources = self.resource_collector.collect_resources(provider)

        affected_resources = []

        for resource_type, resource_list in all_resources.items():
            if resource_type in resource_changes:
                allowed_ids = set(resource_changes[resource_type])

                for resource in resource_list:
                    resource_id = resource.get("Id", resource.get("id", ""))
                    if resource_id in allowed_ids:
                        resource["ResourceType"] = resource_type
                        affected_resources.append(resource)

        return affected_resources

    def _scan_provider(
        self,
        provider: CloudProvider,
        rule_ids: Optional[List[str]] = None,
        resource_filter: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        logger.info(f"Starting scan for provider: {provider}")

        resources = self.resource_collector.collect_resources(provider)

        all_resources = []
        for resource_type, resource_list in resources.items():
            for resource in resource_list:
                if self._filter_resource(resource, resource_filter):
                    resource["ResourceType"] = resource_type
                    all_resources.append(resource)

        if self.config.verbose:
            logger.info(f"Collected {len(all_resources)} resources from {provider}")

        if not all_resources:
            return ScanResult(
                scan_id=self._generate_scan_id(),
                timestamp=datetime.utcnow(),
                cloud_provider=provider,
                total_resources=0,
                scanned_resources=0,
                findings=[],
                summary={
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "compliant": 0,
                },
                duration_seconds=0,
                rules_applied=[],
            )

        result = self.rule_engine.scan_resources(all_resources, provider, rule_ids)

        logger.info(
            f"Scan completed for {provider}: "
            f"{result.summary['total_findings']} findings, "
            f"{result.summary['compliant']} compliant"
        )

        return result

    def _filter_resource(
        self, resource: Dict[str, Any], filter_config: Optional[Dict[str, Any]]
    ) -> bool:
        if not filter_config:
            return True

        resource_id = resource.get("Id", resource.get("id", ""))

        if "exclude_ids" in filter_config:
            if resource_id in filter_config["exclude_ids"]:
                return False

        if "include_tags" in filter_config:
            resource_tags = resource.get("Tags", {})
            if not any(tag in resource_tags for tag in filter_config["include_tags"]):
                return False

        return True

    def _handle_findings(self, result: ScanResult):
        for finding in result.findings:
            if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                self.alert_manager.send_alert(finding)

        if self.config.webhook_url:
            self.report_generator.send_webhook_report(result, self.config.webhook_url)

        if self.config.slack_webhook_url:
            self.report_generator.send_slack_alert(
                result, self.config.slack_webhook_url
            )

    def _save_result(self, result: ScanResult):
        if self.config.s3_bucket:
            self.report_generator.save_to_s3(result, self.config.s3_bucket)

        if self.config.dynamodb_table:
            self._save_to_dynamodb(result)

    def _save_to_dynamodb(self, result: ScanResult):
        try:
            import boto3

            dynamodb = boto3.resource("dynamodb")
            table = dynamodb.Table(self.config.dynamodb_table)

            item = {
                "scan_id": result.scan_id,
                "timestamp": result.timestamp.isoformat(),
                "provider": result.cloud_provider.value,
                "summary": result.summary,
                "findings_count": len(result.findings),
                "rules_applied": result.rules_applied,
                "ttl": int((datetime.utcnow()).timestamp()) + 86400,
            }

            if result.findings:
                item["critical_findings"] = [
                    f for f in result.findings if f.severity == SeverityLevel.CRITICAL
                ]

            table.put_item(Item=item)
        except ImportError:
            logger.warning("boto3 not installed, skipping DynamoDB save")
        except Exception as e:
            logger.error(f"Error saving to DynamoDB: {e}")

    def get_compliance_summary(self, results: Dict[str, ScanResult]) -> Dict[str, Any]:
        summary = {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "total_scans": len(results),
            "overall_score": 0,
            "by_provider": {},
            "critical_findings": [],
            "high_findings": [],
        }

        total_resources = 0
        total_findings = 0

        for provider, result in results.items():
            if not result:
                continue

            total_resources += result.total_resources
            total_findings += result.summary["total_findings"]

            score = 0
            if result.total_resources > 0:
                score = (
                    (result.total_resources - result.summary["total_findings"])
                    / result.total_resources
                    * 100
                )

            provider_key = (
                provider.value if hasattr(provider, "value") else str(provider)
            )
            summary["by_provider"][provider_key] = {
                "score": round(score, 2),
                "resources_scanned": result.total_resources,
                "findings": result.summary,
                "rules_applied": result.rules_applied,
                "duration_seconds": result.duration_seconds,
            }

            summary["critical_findings"].extend(
                [f for f in result.findings if f.severity == SeverityLevel.CRITICAL]
            )
            summary["high_findings"].extend(
                [f for f in result.findings if f.severity == SeverityLevel.HIGH]
            )

        if total_resources > 0:
            summary["overall_score"] = round(
                ((total_resources - total_findings) / total_resources * 100), 2
            )

        summary["total_resources_scanned"] = total_resources
        summary["total_findings"] = total_findings

        return summary

    def run_ci_cd_scan(
        self, provider: CloudProvider, commit_sha: str, pipeline_id: str
    ) -> Dict[str, Any]:
        scan_id = f"cicd-{commit_sha}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        result = self._scan_provider(provider)

        report = {
            "scan_id": scan_id,
            "commit_sha": commit_sha,
            "pipeline_id": pipeline_id,
            "timestamp": datetime.utcnow().isoformat(),
            "provider": provider.value,
            "summary": result.summary,
            "compliance_score": self._calculate_score(result),
            "pass": result.summary["critical"] == 0 and result.summary["high"] == 0,
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
        }

        if not report["pass"]:
            report["failure_reason"] = self._get_failure_reason(result)

        return report

    def _calculate_score(self, result: ScanResult) -> float:
        if result.total_resources == 0:
            return 100.0

        critical_weight = 25
        high_weight = 10
        medium_weight = 5
        low_weight = 1

        penalty = (
            result.summary.get("critical", 0) * critical_weight
            + result.summary.get("high", 0) * high_weight
            + result.summary.get("medium", 0) * medium_weight
            + result.summary.get("low", 0) * low_weight
        )

        max_penalty = result.total_resources * critical_weight
        score = max(0, 100 - (penalty / max_penalty * 100))

        return round(score, 2)

    def _get_failure_reason(self, result: ScanResult) -> str:
        reasons = []
        if result.summary.get("critical", 0) > 0:
            reasons.append(f"{result.summary['critical']} critical violations")
        if result.summary.get("high", 0) > 0:
            reasons.append(f"{result.summary['high']} high severity violations")
        return "; ".join(reasons)

    def scan_terraform_file(self, file_path: str) -> ScanResult:
        from src.collectors.resource_collectors import TerraformResourceCollector

        collector = TerraformResourceCollector(self.config)
        resources = collector._parse_terraform_file(file_path)
        return self.rule_engine.scan_resources(resources, CloudProvider.TERRAFORM)

    def scan_terraform_plan(self, plan_json: Dict[str, Any]) -> ScanResult:
        resources = self._parse_terraform_plan(plan_json)
        return self.rule_engine.scan_resources(resources, CloudProvider.TERRAFORM)

    def _parse_terraform_plan(self, plan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        resources = []

        for resource_change in (
            plan_json.get("planned_values", {})
            .get("root_module", {})
            .get("resources", [])
        ):
            resources.append(
                {
                    "Id": resource_change.get("address", ""),
                    "Name": resource_change.get(
                        "name", resource_change.get("address", "")
                    ),
                    "ResourceType": resource_change.get("type", ""),
                    "values": resource_change.get("values", {}),
                }
            )

        return resources

    def run_continuous_scan(self):
        import time

        logger.info("Starting continuous compliance scanning...")

        while True:
            try:
                results = self.run_scan()

                for provider, result in results.items():
                    if result and result.findings:
                        logger.warning(
                            f"Continuous scan - {provider}: "
                            f"{result.summary['total_findings']} findings"
                        )

                time.sleep(3600)

            except KeyboardInterrupt:
                logger.info("Stopping continuous scan...")
                break
            except Exception as e:
                logger.error(f"Error in continuous scan: {e}")
                time.sleep(60)

    def _generate_scan_id(self) -> str:
        return f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:8]}"

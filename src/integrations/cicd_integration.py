import json
import os
import subprocess
import sys
import yaml
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from enum import Enum


class CICDPlatform(Enum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    CIRCLECI = "circleci"


@dataclass
class ScanConfig:
    provider: str
    commit_sha: str
    branch: str
    repository: str
    pipeline_id: str
    threshold_score: int = 80
    fail_on_critical: bool = True
    fail_on_high: bool = True
    output_format: str = "json"
    additional_rules: Optional[List[str]] = None


class BaseCICDIntegrator:
    def __init__(self, platform: CICDPlatform):
        self.platform = platform

    def generate_scan_step(self, config: ScanConfig) -> Dict[str, Any]:
        raise NotImplementedError

    def generate_result_parser(self, config: ScanConfig) -> str:
        raise NotImplementedError

    def generate_gate_condition(self, config: ScanConfig) -> str:
        raise NotImplementedError


class GitHubActionsIntegrator(BaseCICDIntegrator):
    def __init__(self):
        super().__init__(CICDPlatform.GITHUB_ACTIONS)

    def generate_scan_step(self, config: ScanConfig) -> Dict[str, Any]:
        return {
            "name": "Zero-Trust Compliance Scan",
            "uses": "docker://public.ecr.aws/zerotrust/compliance-scanner:latest",
            "if": f"github.event_name == 'pull_request' || github.event_name == 'push'",
            "env": {
                "AWS_REGION": os.environ.get("AWS_REGION", "us-east-1"),
                "COMPLIANCE_PROVIDER": config.provider,
                "COMPLIANCE_THRESHOLD": str(config.threshold_score),
                "FAIL_ON_CRITICAL": str(config.fail_on_critical).lower(),
                "FAIL_ON_HIGH": str(config.fail_on_high).lower(),
            },
            "with": {
                "args": f"scan --provider {config.provider} --commit-sha ${{ github.sha }} --output-format json",
            },
        }

    def generate_result_parser(self, config: ScanConfig) -> str:
        return """
        - name: Parse Compliance Results
          id: parse-results
          run: |
            if [ -f compliance_report.json ]; then
              echo "::set-output name=score::$(cat compliance_report.json | jq -r '.compliance_score')"
              echo "::set-output name=pass::$(cat compliance_report.json | jq -r '.pass')"
              echo "::set-output name=findings::$(cat compliance_report.json | jq -r '.findings | length')"
            else
              echo "::set-output name=score::100"
              echo "::set-output name=pass::true"
              echo "::set-output name=findings::0"
            fi
        
        - name: Upload Compliance Report
          uses: actions/upload-artifact@v3
          if: always()
          with:
            name: compliance-report
            path: compliance_report.json
        """

    def generate_gate_condition(self, config: ScanConfig) -> str:
        return f"""
        - name: Compliance Gate
          if: always()
          run: |
            score="${{ steps.parse-results.outputs.score }}"
            pass="${{ steps.parse-results.outputs.pass }}"
            findings="${{ steps.parse-results.outputs.findings }}"
            
            echo "Compliance Score: $score"
            echo "Findings: $findings"
            
            if [ "$pass" == "false" ]; then
              echo "❌ Compliance check FAILED"
              cat compliance_report.json | jq '.findings[] | select(.severity == "critical" or .severity == "high")'
              exit 1
            elif [ "$score" -lt {config.threshold_score} ]; then
              echo "⚠️  Compliance score ($score) below threshold ({config.threshold_score})"
              exit 1
            else
              echo "✅ Compliance check PASSED (Score: $score)"
            fi
        """

    def generate_workflow(self, config: ScanConfig) -> str:
        workflow = f"""
name: Zero-Trust Compliance Scan

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master]

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-region: ${{ env.AWS_REGION }}
          role-to-assume: ${{ secrets.COMPLIANCE_SCAN_ROLE_ARN }}
      
      - name: Run Compliance Scan
        id: scan
        run: |
          pip install zerotrust-compliance-scanner
          compliance-scan scan \\
            --provider {config.provider} \\
            --commit-sha ${{ github.sha }} \\
            --pipeline-id ${{ github.run_id }} \\
            --output-format json \\
            > compliance_report.json
          cat compliance_report.json
      
      {self.generate_result_parser(config)}
      
      {self.generate_gate_condition(config)}
        """
        return workflow.strip()


class GitLabCIIntegrator(BaseCICDIntegrator):
    def __init__(self):
        super().__init__(CICDPlatform.GITLAB_CI)

    def generate_scan_step(self, config: ScanConfig) -> Dict[str, Any]:
        return {
            "image": "public.ecr.aws/zerotrust/compliance-scanner:latest",
            "stage": "security",
            "script": [
                f"compliance-scan scan --provider {config.provider} --commit-sha $CI_COMMIT_SHA --output-format json > compliance_report.json",
                "cat compliance_report.json",
            ],
            "artifacts": {
                "paths": ["compliance_report.json"],
                "when": "always",
            },
            "rules": [
                {"if": "$CI_PIPELINE_SOURCE == 'merge_request_event'"},
                {"if": "$CI_COMMIT_BRANCH == 'main'"},
            ],
        }

    def generate_gate_condition(self, config: ScanConfig) -> str:
        return f"""
        compliance_gate:
          stage: security
          image: alpine:latest
          script:
            - apk add jq curl
            - |
              score=$(cat compliance_report.json | jq -r '.compliance_score')
              pass=$(cat compliance_report.json | jq -r '.pass')
              findings=$(cat compliance_report.json | jq -r '.findings | length')
              
              echo "Compliance Score: $score"
              echo "Findings: $findings"
              
              if [ "$pass" == "false" ]; then
                echo "Compliance check FAILED"
                exit 1
              elif [ "$score" -lt {config.threshold_score} ]; then
                echo "Compliance score ($score) below threshold ({config.threshold_score})"
                exit 1
              fi
          rules:
            - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
            - if: $CI_COMMIT_BRANCH == 'main'
        """

    def generate_result_parser(self, config: ScanConfig) -> str:
        return """
        - apk add jq
        - |
          if [ -f compliance_report.json ]; then
            score=$(cat compliance_report.json | jq -r '.compliance_score')
            pass=$(cat compliance_report.json | jq -r '.pass')
            findings=$(cat compliance_report.json | jq -r '.findings | length')
            echo "Score: $score"
            echo "Findings: $findings"
          fi
        """

    def generate_ci_yaml(self, config: ScanConfig) -> str:
        import yaml

        return f"""
stages:
  - security
  - gate

compliance_scan:
{yaml.dump(self.generate_scan_step(config), default_flow_style=False)}

{self.generate_gate_condition(config)}
        """


class AzureDevOpsIntegrator(BaseCICDIntegrator):
    def __init__(self):
        super().__init__(CICDPlatform.AZURE_DEVOPS)

    def generate_task(self, config: ScanConfig) -> Dict[str, Any]:
        return {
            "task": "Bash@3",
            "inputs": {
                "targetType": "inline",
                "script": f"""
                    pip install zerotrust-compliance-scanner
                    compliance-scan scan \
                      --provider {config.provider} \
                      --commit-sha $(Build.SourceVersion) \
                      --pipeline-id $(Build.BuildId) \
                      --output-format json > compliance_report.json
                    
                    echo "##vso[task.setvariable variable=complianceScore;isOutput=true]$(cat compliance_report.json | jq -r '.compliance_score')"
                    echo "##vso[task.setvariable variable=compliancePass;isOutput=true]$(cat compliance_report.json | jq -r '.pass')"
                """,
            },
            "env": {
                "AWS_REGION": "$(AWS_REGION)",
                "COMPLIANCE_PROVIDER": config.provider,
            },
        }

    def generate_gate(self, config: ScanConfig) -> Dict[str, Any]:
        return {
            "task": "Gate@0",
            "inputs": {
                "tasks": [
                    {
                        "task": "Bash@3",
                        "inputs": {
                            "targetType": "inline",
                            "script": """
                                score=$(cat compliance_report.json | jq -r '.compliance_score')
                                pass=$(cat compliance_report.json | jq -r '.pass')
                                
                                if [ "$pass" == "false" ]; then
                                  echo "##vso[task.logissue type=error]Compliance check FAILED"
                                  exit 1
                                elif [ "$score" -lt 80 ]; then
                                  echo "##vso[task.logissue type=warning]Compliance score ($score) below threshold"
                                fi
                            """,
                        },
                    },
                ],
            },
        }


class ComplianceGateValidator:
    def __init__(self):
        self.thresholds = {
            "critical": 0,
            "high": 0,
            "medium": 5,
            "low": 10,
            "minimum_score": 80,
        }

    def validate_result(
        self, report: Dict[str, Any], custom_thresholds: Optional[Dict[str, int]] = None
    ) -> Dict[str, Any]:
        thresholds = self.thresholds.copy()
        if custom_thresholds:
            thresholds.update(custom_thresholds)

        findings = report.get("findings", [])
        summary = report.get("findings_summary", {})

        critical = summary.get(
            "critical", len([f for f in findings if f.get("severity") == "critical"])
        )
        high = summary.get(
            "high", len([f for f in findings if f.get("severity") == "high"])
        )
        medium = summary.get(
            "medium", len([f for f in findings if f.get("severity") == "medium"])
        )
        low = summary.get(
            "low", len([f for f in findings if f.get("severity") == "low"])
        )

        score = report.get("compliance_score", 100)

        validation = {
            "passed": True,
            "score": score,
            "thresholds_applied": thresholds,
            "violations": [],
            "summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
        }

        if critical > thresholds["critical"]:
            validation["passed"] = False
            validation["violations"].append(
                {
                    "type": "critical_violations",
                    "count": critical,
                    "limit": thresholds["critical"],
                    "message": f"Found {critical} critical violations (limit: {thresholds['critical']})",
                }
            )

        if high > thresholds["high"]:
            validation["passed"] = False
            validation["violations"].append(
                {
                    "type": "high_violations",
                    "count": high,
                    "limit": thresholds["high"],
                    "message": f"Found {high} high-severity violations (limit: {thresholds['high']})",
                }
            )

        if medium > thresholds["medium"]:
            validation["violations"].append(
                {
                    "type": "medium_violations",
                    "count": medium,
                    "limit": thresholds["medium"],
                    "message": f"Found {medium} medium-severity violations (warning only)",
                }
            )

        if score < thresholds["minimum_score"]:
            validation["passed"] = False
            validation["violations"].append(
                {
                    "type": "score_below_threshold",
                    "score": score,
                    "threshold": thresholds["minimum_score"],
                    "message": f"Compliance score ({score}) below minimum threshold ({thresholds['minimum_score']})",
                }
            )

        return validation

    def generate_pull_request_comment(
        self, validation: Dict[str, Any], report: Dict[str, Any]
    ) -> str:
        score = validation["score"]

        if validation["passed"]:
            emoji = "✅"
            color = "#28a745"
        else:
            emoji = "❌"
            color = "#dc3545"

        summary = validation["summary"]

        comment = f"""
## Zero-Trust Compliance Report {emoji}

| Metric | Value | Status |
|--------|-------|--------|
| **Compliance Score** | {score}% | {"✅ PASS" if score >= 80 else "⚠️  WARNING"} |
| **Critical Issues** | {summary["critical"]} | {"✅" if summary["critical"] == 0 else "❌"} |
| **High Issues** | {summary["high"]} | {"✅" if summary["high"] == 0 else "❌"} |
| **Medium Issues** | {summary["medium"]} | |
| **Low Issues** | {summary["low"]} | |

### Violations Detected
"""
        for violation in validation.get("violations", []):
            comment += f"- **{violation['type']}**: {violation['message']}\n"

        if not validation["violations"]:
            comment += "_No violations detected_\n"

        if report.get("findings"):
            comment += "\n### Top Findings\n"
            for finding in report["findings"][:5]:
                comment += f"- `{finding.get('rule_id', 'N/A')}`: {finding.get('message', '')[:80]}...\n"

        return comment


def create_cicd_pipeline(platform: CICDPlatform, config: ScanConfig) -> str:
    integrators = {
        CICDPlatform.GITHUB_ACTIONS: GitHubActionsIntegrator(),
        CICDPlatform.GITLAB_CI: GitLabCIIntegrator(),
        CICDPlatform.AZURE_DEVOPS: AzureDevOpsIntegrator(),
    }

    integrator = integrators.get(platform)
    if not integrator:
        raise ValueError(f"Unsupported CI/CD platform: {platform}")

    if platform == CICDPlatform.GITHUB_ACTIONS:
        return integrator.generate_workflow(config)
    elif platform == CICDPlatform.GITLAB_CI:
        return integrator.generate_ci_yaml(config)
    else:
        raise ValueError(f"YAML generation not implemented for {platform}")


def run_cli_scan(config: ScanConfig) -> Dict[str, Any]:
    from ..scanners.compliance_scanner import ComplianceScanner
    from ..config import CloudProvider, ScannerConfig

    provider = CloudProvider(config.provider)

    scanner_config = ScannerConfig(
        enabled_providers=[provider],
        dry_run=False,
        verbose=True,
    )

    scanner = ComplianceScanner(scanner_config)
    report = scanner.run_ci_cd_scan(
        provider=provider,
        commit_sha=config.commit_sha,
        pipeline_id=config.pipeline_id,
    )

    validator = ComplianceGateValidator()
    validation = validator.validate_result(report)

    result = {
        "compliance_score": report["compliance_score"],
        "pass": validation["passed"],
        "findings": report.get("findings", []),
        "findings_summary": {
            "critical": len(
                [
                    f
                    for f in report.get("findings", [])
                    if f.get("severity") == "critical"
                ]
            ),
            "high": len(
                [f for f in report.get("findings", []) if f.get("severity") == "high"]
            ),
            "medium": len(
                [f for f in report.get("findings", []) if f.get("severity") == "medium"]
            ),
            "low": len(
                [f for f in report.get("findings", []) if f.get("severity") == "low"]
            ),
        },
        "validation": validation,
    }

    if config.output_format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Compliance Score: {result['compliance_score']}%")
        print(f"Status: {'PASS' if result['pass'] else 'FAIL'}")
        print(f"Critical: {result['findings_summary']['critical']}")
        print(f"High: {result['findings_summary']['high']}")

    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Zero-Trust Compliance Scanner CLI")
    parser.add_argument("command", choices=["scan", "generate", "validate"])
    parser.add_argument(
        "--provider", required=True, choices=["aws", "azure", "gcp", "terraform"]
    )
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--branch", default=os.environ.get("GITHUB_REF", "unknown"))
    parser.add_argument(
        "--repository", default=os.environ.get("GITHUB_REPOSITORY", "unknown")
    )
    parser.add_argument(
        "--pipeline-id", default=os.environ.get("GITHUB_RUN_ID", "unknown")
    )
    parser.add_argument("--threshold-score", type=int, default=80)
    parser.add_argument("--output-format", choices=["json", "text"], default="text")

    args = parser.parse_args()

    if args.command == "scan":
        config = ScanConfig(
            provider=args.provider,
            commit_sha=args.commit_sha,
            branch=args.branch,
            repository=args.repository,
            pipeline_id=args.pipeline_id,
            threshold_score=args.threshold_score,
            output_format=args.output_format,
        )
        result = run_cli_scan(config)
        sys.exit(0 if result["pass"] else 1)

    elif args.command == "generate":
        config = ScanConfig(
            provider=args.provider,
            commit_sha=args.commit_sha,
            branch=args.branch,
            repository=args.repository,
            pipeline_id=args.pipeline_id,
        )
        workflow = create_cicd_pipeline(CICDPlatform.GITHUB_ACTIONS, config)
        print(workflow)

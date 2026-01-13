"""
Dependency Vulnerability Scanner for Zero-Trust Compliance Scanner.

Scans Python dependencies for known security vulnerabilities using
safety, pip-audit, or OSV (Open Source Vulnerability) database.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VulnerabilitySource(Enum):
    SAFETY = "safety"
    PIP_AUDIT = "pip-audit"
    OSV = "osv"
    MANUAL = "manual"


@dataclass
class DependencyVulnerability:
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_in_version: Optional[str]
    severity: VulnerabilitySeverity
    description: str
    advisory: str
    published_date: Optional[datetime]
    source: VulnerabilitySource
    cve_id: Optional[str] = None
    vulnerable_versions: Optional[str] = None


@dataclass
class DependencyScanResult:
    scanned_at: datetime
    total_dependencies: int
    vulnerable_packages: int
    vulnerabilities: List[DependencyVulnerability]
    scan_source: VulnerabilitySource
    raw_output: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanned_at": self.scanned_at.isoformat(),
            "total_dependencies": self.total_dependencies,
            "vulnerable_packages": self.vulnerable_packages,
            "vulnerabilities": [
                {
                    "vulnerability_id": v.vulnerability_id,
                    "package_name": v.package_name,
                    "installed_version": v.installed_version,
                    "fixed_in_version": v.fixed_in_version,
                    "severity": v.severity.value,
                    "description": v.description,
                    "advisory": v.advisory,
                    "published_date": v.published_date.isoformat()
                    if v.published_date
                    else None,
                    "source": v.source.value,
                    "cve_id": v.cve_id,
                    "vulnerable_versions": v.vulnerable_versions,
                }
                for v in self.vulnerabilities
            ],
            "scan_source": self.scan_source.value,
        }


class DependencyScanner:
    def __init__(self, requirements_file: str = "requirements.txt"):
        self.requirements_file = requirements_file
        self.vulnerability_sources: List[VulnerabilitySource] = [
            VulnerabilitySource.SAFETY,
            VulnerabilitySource.PIP_AUDIT,
        ]

    def scan(self) -> DependencyScanResult:
        vulnerabilities: List[DependencyVulnerability] = []

        for source in self.vulnerability_sources:
            try:
                if source == VulnerabilitySource.SAFETY:
                    vulns = self._scan_with_safety()
                    vulnerabilities.extend(vulns)
                elif source == VulnerabilitySource.PIP_AUDIT:
                    vulns = self._scan_with_pip_audit()
                    vulnerabilities.extend(vulns)
            except Exception as e:
                logger.warning(f"Failed to scan with {source.value}: {e}")

        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)

        return DependencyScanResult(
            scanned_at=datetime.utcnow(),
            total_dependencies=self._count_dependencies(),
            vulnerable_packages=len(set(v.package_name for v in unique_vulns)),
            vulnerabilities=unique_vulns,
            scan_source=VulnerabilitySource.SAFETY,
        )

    def _count_dependencies(self) -> int:
        try:
            with open(self.requirements_file, "r") as f:
                lines = f.readlines()
                return len(
                    [l for l in lines if l.strip() and not l.strip().startswith("#")]
                )
        except FileNotFoundError:
            return 0

    def _scan_with_safety(self) -> List[DependencyVulnerability]:
        vulnerabilities: List[DependencyVulnerability] = []

        try:
            result = subprocess.run(
                ["safety", "check", "-r", self.requirements_file, "--json"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode in [0, 1]:
                try:
                    data = json.loads(result.stdout)
                    for vuln in data:
                        severity = self._map_severity(vuln.get("severity", "unknown"))
                        published_date = None
                        if vuln.get("published_date"):
                            try:
                                published_date = datetime.fromisoformat(
                                    vuln["published_date"].replace("Z", "+00:00")
                                )
                            except ValueError:
                                pass

                        vulnerabilities.append(
                            DependencyVulnerability(
                                vulnerability_id=vuln.get(
                                    "id", vuln.get("vulnerability_id", "")
                                ),
                                package_name=vuln.get("package", ""),
                                installed_version=vuln.get("installed_version", ""),
                                fixed_in_version=vuln.get("fixed_in", None),
                                severity=severity,
                                description=vuln.get("description", ""),
                                advisory=vuln.get("advisory", ""),
                                published_date=published_date,
                                source=VulnerabilitySource.SAFETY,
                                cve_id=vuln.get("cve_id", None),
                                vulnerable_versions=vuln.get(
                                    "vulnerable_versions", None
                                ),
                            )
                        )
                except json.JSONDecodeError:
                    logger.warning("Failed to parse safety JSON output")

        except FileNotFoundError:
            logger.info("Safety not installed, skipping safety scan")
        except subprocess.TimeoutExpired:
            logger.warning("Safety scan timed out")

        return vulnerabilities

    def _scan_with_pip_audit(self) -> List[DependencyVulnerability]:
        vulnerabilities: List[DependencyVulnerability] = []

        try:
            result = subprocess.run(
                ["pip-audit", "-r", self.requirements_file, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode in [0, 1]:
                try:
                    data = json.loads(result.stdout)
                    for vuln in data.get("results", []):
                        for pkg in vuln.get("packages", []):
                            for vul in pkg.get("vulnerabilities", []):
                                severity = self._map_severity(
                                    vul.get("severity_id", "unknown")
                                )
                                published_date = None
                                if vul.get("published"):
                                    try:
                                        published_date = datetime.fromisoformat(
                                            vul["published"].replace("Z", "+00:00")
                                        )
                                    except ValueError:
                                        pass

                                vulnerabilities.append(
                                    DependencyVulnerability(
                                        vulnerability_id=vul.get("id", ""),
                                        package_name=pkg.get("name", ""),
                                        installed_version=pkg.get("version", ""),
                                        fixed_in_version=vul.get(
                                            "fix_versions", [None]
                                        )[0]
                                        if vul.get("fix_versions")
                                        else None,
                                        severity=severity,
                                        description=vul.get("description", ""),
                                        advisory=vul.get("advisory", ""),
                                        published_date=published_date,
                                        source=VulnerabilitySource.PIP_AUDIT,
                                        cve_id=vul.get("cve_ids", [None])[0]
                                        if vul.get("cve_ids")
                                        else None,
                                        vulnerable_versions=vul.get(
                                            "vulnerable_versions", None
                                        ),
                                    )
                                )
                except json.JSONDecodeError:
                    logger.warning("Failed to parse pip-audit JSON output")

        except FileNotFoundError:
            logger.info("pip-audit not installed, skipping pip-audit scan")
        except subprocess.TimeoutExpired:
            logger.warning("pip-audit scan timed out")

        return vulnerabilities

    def _map_severity(self, severity_str: str) -> VulnerabilitySeverity:
        severity_map: Dict[str, VulnerabilitySeverity] = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "moderate": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.LOW,
            "unknown": VulnerabilitySeverity.UNKNOWN,
        }
        return severity_map.get(severity_str.lower(), VulnerabilitySeverity.UNKNOWN)

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: List[DependencyVulnerability]
    ) -> List[DependencyVulnerability]:
        seen: Dict[str, DependencyVulnerability] = {}
        for vuln in vulnerabilities:
            key = f"{vuln.package_name}:{vuln.vulnerability_id}"
            if key not in seen:
                seen[key] = vuln
        return list(seen.values())


def scan_dependencies(
    requirements_file: str = "requirements.txt",
) -> DependencyScanResult:
    scanner = DependencyScanner(requirements_file)
    return scanner.scan()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    requirements_file = sys.argv[1] if len(sys.argv) > 1 else "requirements.txt"
    result = scan_dependencies(requirements_file)

    print(f"\nDependency Vulnerability Scan Results")
    print(f"=" * 50)
    print(f"Scanned at: {result.scanned_at.isoformat()}")
    print(f"Total dependencies: {result.total_dependencies}")
    print(f"Vulnerable packages: {result.vulnerable_packages}")
    print(f"Total vulnerabilities: {len(result.vulnerabilities)}")
    print()

    for vuln in result.vulnerabilities:
        print(
            f"[{vuln.severity.value.upper()}] {vuln.package_name}@{vuln.installed_version}"
        )
        print(f"  ID: {vuln.vulnerability_id}")
        if vuln.cve_id:
            print(f"  CVE: {vuln.cve_id}")
        if vuln.fixed_in_version:
            print(f"  Fix: Upgrade to {vuln.fixed_in_version}")
        print(f"  {vuln.description[:100]}...")
        print()

    output_file = "dependency_scan_results.json"
    with open(output_file, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"Results saved to {output_file}")

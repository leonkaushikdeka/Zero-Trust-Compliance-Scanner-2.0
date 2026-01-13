"""
Performance Benchmarks for Zero-Trust Compliance Scanner.

Provides benchmarking utilities to measure and track scanning performance
across different resource counts and cloud providers.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    name: str
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    throughput_per_sec: float
    memory_peak_mb: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "total_time_ms": self.total_time_ms,
            "avg_time_ms": self.avg_time_ms,
            "min_time_ms": self.min_time_ms,
            "max_time_ms": self.max_time_ms,
            "throughput_per_sec": self.throughput_per_sec,
            "memory_peak_mb": self.memory_peak_mb,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


class PerformanceBenchmark:
    def __init__(self, warmup_iterations: int = 1, verbose: bool = True):
        self.warmup_iterations = warmup_iterations
        self.verbose = verbose

    def benchmark(
        self,
        name: str,
        func: Callable,
        iterations: int = 10,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> BenchmarkResult:
        times: List[float] = []

        for i in range(self.warmup_iterations):
            if self.verbose:
                logger.info(f"Warmup iteration {i + 1}/{self.warmup_iterations}")
            func()

        for i in range(iterations):
            if self.verbose:
                logger.info(f"Benchmark iteration {i + 1}/{iterations}")
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            times.append((end - start) * 1000)

        total_time = sum(times)
        avg_time = total_time / len(times)

        result = BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time_ms=total_time,
            avg_time_ms=avg_time,
            min_time_ms=min(times),
            max_time_ms=max(times),
            throughput_per_sec=iterations / (total_time / 1000)
            if total_time > 0
            else 0,
            metadata=metadata or {},
        )

        if self.verbose:
            self._log_result(result)

        return result

    def benchmark_with_args(
        self,
        name: str,
        func: Callable,
        args_list: List[tuple],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[BenchmarkResult]:
        results: List[BenchmarkResult] = []

        for args in args_list:
            result = self.benchmark(
                name=f"{name} [{args}]",
                func=lambda a=args: func(*a),
                iterations=1,
                metadata=metadata,
            )
            results.append(result)

        return results

    def _log_result(self, result: BenchmarkResult) -> None:
        logger.info(f"\n{'=' * 60}")
        logger.info(f"Benchmark Results: {result.name}")
        logger.info(f"{'=' * 60}")
        logger.info(f"Iterations:      {result.iterations}")
        logger.info(f"Total time:      {result.total_time_ms:.2f} ms")
        logger.info(f"Average time:    {result.avg_time_ms:.2f} ms")
        logger.info(f"Min time:        {result.min_time_ms:.2f} ms")
        logger.info(f"Max time:        {result.max_time_ms:.2f} ms")
        logger.info(f"Throughput:      {result.throughput_per_sec:.2f} ops/sec")
        if result.memory_peak_mb:
            logger.info(f"Memory peak:     {result.memory_peak_mb:.2f} MB")
        logger.info(f"{'=' * 60}\n")


class ComplianceScannerBenchmark:
    def __init__(self):
        self.benchmark_suite = PerformanceBenchmark(warmup_iterations=1, verbose=False)

    def benchmark_rule_engine(
        self, resources: List[Dict[str, Any]], iterations: int = 10
    ) -> BenchmarkResult:
        from src.core.rule_engine import RuleEngine
        from src.core.config import CloudProvider

        engine = RuleEngine()

        def scan():
            engine.scan_resources(resources, CloudProvider.AWS)

        return self.benchmark_suite.benchmark(
            name="RuleEngine.scan_resources",
            func=scan,
            iterations=iterations,
            metadata={"resource_count": len(resources)},
        )

    def benchmark_resource_collection(
        self, provider: str, iterations: int = 10
    ) -> BenchmarkResult:
        from src.collectors.resource_collectors import AWSResourceCollector

        collector = AWSResourceCollector()

        def collect():
            collector.collect_resources()

        return self.benchmark_suite.benchmark(
            name=f"{provider}ResourceCollector.collect_resources",
            func=collect,
            iterations=iterations,
            metadata={"provider": provider},
        )

    def benchmark_compliance_scan(
        self, resources: List[Dict[str, Any]], iterations: int = 10
    ) -> BenchmarkResult:
        from src.scanners.compliance_scanner import ComplianceScanner
        from src.core.config import CloudProvider, ScannerConfig

        config = ScannerConfig(
            cloud_provider=CloudProvider.AWS,
            enabled_rules=None,
            severity_filter=None,
        )
        scanner = ComplianceScanner(config)

        def scan():
            scanner.scan(resources)

        return self.benchmark_suite.benchmark(
            name="ComplianceScanner.scan",
            func=scan,
            iterations=iterations,
            metadata={"resource_count": len(resources)},
        )

    def run_full_benchmark(
        self, resource_counts: List[int] = [10, 50, 100, 500]
    ) -> Dict[str, Any]:
        results: Dict[str, Any] = {}

        for count in resource_counts:
            logger.info(f"\n{'#' * 60}")
            logger.info(f"# Benchmarking with {count} resources")
            logger.info(f"{'#' * 60}")

            resources = self._generate_mock_resources(count)

            rule_result = self.benchmark_rule_engine(resources, iterations=5)
            results[f"rule_engine_{count}"] = rule_result.to_dict()

            scan_result = self.benchmark_compliance_scan(resources, iterations=5)
            results[f"compliance_scan_{count}"] = scan_result.to_dict()

        return results

    def _generate_mock_resources(self, count: int) -> List[Dict[str, Any]]:
        resources = []
        for i in range(count):
            resources.append(
                {
                    "Id": f"sg-{i:04d}",
                    "Name": f"security-group-{i}",
                    "ResourceType": "AWS::EC2::SecurityGroup",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                    "Tags": [{"Key": "Environment", "Value": "production"}],
                }
            )
        return resources


def run_benchmarks(output_file: str = "benchmark_results.json") -> None:
    logging.basicConfig(level=logging.INFO)

    benchmark = ComplianceScannerBenchmark()
    results = benchmark.run_full_benchmark(resource_counts=[10, 50, 100])

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nBenchmark results saved to {output_file}")

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for key, result in results.items():
        print(f"\n{key}:")
        print(f"  Avg time: {result['avg_time_ms']:.2f} ms")
        print(f"  Throughput: {result['throughput_per_sec']:.2f} ops/sec")


if __name__ == "__main__":
    import sys

    output_file = sys.argv[1] if len(sys.argv) > 1 else "benchmark_results.json"
    run_benchmarks(output_file)

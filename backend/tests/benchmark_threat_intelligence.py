"""
Threat Intelligence Performance & Latency Benchmark Suite.

Phase 4.2B.6 — Final Threat Intelligence Validation, Benchmarking & Security Audit.

Measures throughput (items/sec) and latency distributions (avg, median, p95, p99) for:
1. IOC extraction throughput across batch sizes (100, 1k, 5k, 10k log lines).
2. IOC normalization & validation latency.
3. Threat reputation engine scoring latency.
4. Threat correlation engine latency against a populated enterprise-scale SessionStore.
5. Unified threat context assembly latency.

NOTE: All benchmark results are designated as "Synthetic / Controlled Validation".
"""

from datetime import datetime, timezone
import math
import os
import statistics
import sys
import time
from typing import Any, Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.anomaly import Anomaly, DetectionMethod, SeverityLevel
from app.models.attack_chain import AttackChain, AttackStage, ChainLinkEvent, ChainStatus
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    ThreatSeverity,
)
from app.services.ioc_extractor import IOCExtractor
from app.services.ioc_normalizer import IOCNormalizer
from app.services.ioc_repository import IOCRepository
from app.services.ioc_validator import IOCValidator
from app.services.store import SessionStore
from app.services.threat_correlation_engine import ThreatCorrelationEngine
from app.services.threat_reputation_engine import ThreatReputationEngine


def _percentiles(values: List[float]) -> Dict[str, float]:
    """Calculate avg, median, p95, and p99 from a list of durations in milliseconds."""
    if not values:
        return {"avg": 0.0, "median": 0.0, "p95": 0.0, "p99": 0.0}
    sorted_v = sorted(values)
    n = len(sorted_v)
    avg = statistics.mean(sorted_v)
    med = statistics.median(sorted_v)
    p95_idx = min(int(math.ceil(0.95 * n)) - 1, n - 1)
    p99_idx = min(int(math.ceil(0.99 * n)) - 1, n - 1)
    return {
        "avg": round(avg, 4),
        "median": round(med, 4),
        "p95": round(sorted_v[p95_idx], 4),
        "p99": round(sorted_v[p99_idx], 4),
    }


def benchmark_ioc_extraction():
    print("\n" + "=" * 70)
    print("1. IOC EXTRACTION BENCHMARK (Batch Sizes: 100, 1k, 5k, 10k lines)")
    print("=" * 70)

    sample_lines = [
        "Inbound connection from 192.168.1.105:443 to internal gateway",
        "Failed SSH authentication from 198.51.100.23 user root",
        "DNS lookup for evil-c2-domain.com resolved to 185.220.101.5",
        "Download initiated http://malicious.example.com/beacon.exe",
        "Calculated SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Sender address alert-phish@suspicious.org flagged by transport",
        "Access attempted on /etc/shadow by UID 1000",
        "Routine health check: system uptime normal 100% services online",
        "Heartbeat 2026-11-06T12:00:00Z from node-42",
        "MAC 00:1A:2B:3C:4D:5E renegotiated interface link eth0",
    ]

    results = {}
    for batch_size in [100, 1000, 5000, 10000]:
        lines = [sample_lines[i % len(sample_lines)] for i in range(batch_size)]
        text_block = "\n".join(lines)

        t0 = time.perf_counter()
        res = IOCExtractor.extract_from_text(text_block)
        elapsed = time.perf_counter() - t0

        throughput = batch_size / elapsed if elapsed > 0 else 0.0
        results[batch_size] = {
            "batch_size": batch_size,
            "total_extracted": res.total_extracted,
            "unique_iocs": res.unique_iocs,
            "duration_ms": round(elapsed * 1000.0, 2),
            "throughput_lines_sec": round(throughput, 1),
        }
        print(f"Batch {batch_size:6d} lines | Duration: {elapsed*1000.0:8.2f} ms | Throughput: {throughput:9.1f} lines/sec | Extracted: {res.total_extracted:5d} IOCs ({res.unique_iocs} unique)")

    return results


def benchmark_normalization_and_validation(iterations: int = 2000):
    print("\n" + "=" * 70)
    print(f"2. IOC NORMALIZATION & VALIDATION BENCHMARK ({iterations} iterations)")
    print("=" * 70)

    test_samples = [
        (" 192.168.001.001 ", IOCType.IPV4),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", IOCType.IPV6),
        ("EVIL-DOMAIN.COM.", IOCType.DOMAIN),
        ("HTTP://Victim.COM:80/path?id=1", IOCType.URL),
        ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", IOCType.SHA256),
        ("User@Example.COM", IOCType.EMAIL),
        ("/usr/local//bin/python3", IOCType.FILE_PATH),
    ]

    norm_latencies = []
    val_latencies = []

    for i in range(iterations):
        raw, ioc_type = test_samples[i % len(test_samples)]

        t0 = time.perf_counter()
        normalized = IOCNormalizer.normalize(raw, ioc_type)
        norm_latencies.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        _ = IOCValidator.validate(normalized, ioc_type)
        val_latencies.append((time.perf_counter() - t1) * 1000.0)

    norm_stats = _percentiles(norm_latencies)
    val_stats = _percentiles(val_latencies)

    print(f"Normalization | Avg: {norm_stats['avg']:.4f} ms | Med: {norm_stats['median']:.4f} ms | p95: {norm_stats['p95']:.4f} ms | p99: {norm_stats['p99']:.4f} ms")
    print(f"Validation    | Avg: {val_stats['avg']:.4f} ms | Med: {val_stats['median']:.4f} ms | p95: {val_stats['p95']:.4f} ms | p99: {val_stats['p99']:.4f} ms")

    return {"normalization": norm_stats, "validation": val_stats}


def benchmark_reputation_engine(iterations: int = 1500):
    print("\n" + "=" * 70)
    print(f"3. THREAT REPUTATION ENGINE BENCHMARK ({iterations} assessments)")
    print("=" * 70)

    engine = ThreatReputationEngine()
    test_results = [
        ThreatIntelResult(
            ioc_id=f"ioc-{i}",
            ioc_type=IOCType.IPV4,
            ioc_value=f"185.220.101.{i % 250}",
            normalized_value=f"185.220.101.{i % 250}",
            status=ThreatIntelStatus.MALICIOUS if i % 2 == 0 else ThreatIntelStatus.SUSPICIOUS,
            confidence=0.92,
            detection_count=18,
            total_engines=20,
            reputation_score=0.9,
            categories=["c2", "ransomware"] if i % 2 == 0 else ["scanner"],
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
        )
        for i in range(50)
    ]

    latencies = []
    for i in range(iterations):
        ti = test_results[i % len(test_results)]
        t0 = time.perf_counter()
        _ = engine.assess(ti)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    stats = _percentiles(latencies)
    throughput = iterations / (sum(latencies) / 1000.0) if sum(latencies) > 0 else 0.0
    print(f"Assessments   | Avg: {stats['avg']:.4f} ms | Med: {stats['median']:.4f} ms | p95: {stats['p95']:.4f} ms | p99: {stats['p99']:.4f} ms | Throughput: {throughput:.1f} ops/sec")

    return stats


def benchmark_correlation_and_unified_context(iterations: int = 500):
    print("\n" + "=" * 70)
    print(f"4. THREAT CORRELATION & UNIFIED CONTEXT BENCHMARK ({iterations} runs)")
    print("   Populated Store: 100 anomalies, 50 incidents, 20 attack chains")
    print("=" * 70)

    store = SessionStore()
    ioc_repo = IOCRepository(session_store=store)
    engine = ThreatCorrelationEngine(ioc_repo=ioc_repo, session_store=store)
    sess_id = "bench-session"
    now = datetime(2026, 11, 6, 12, 0, 0, tzinfo=timezone.utc)

    # Populate 100 anomalies
    anomalies = []
    for i in range(100):
        anom = Anomaly(
            id=f"anom-b-{i}",
            session_id=sess_id,
            log_entry_ids=[f"evt-b-{i}"],
            score=0.7 + (i % 30) * 0.01,
            severity=SeverityLevel.HIGH if i % 2 == 0 else SeverityLevel.MEDIUM,
            reason=f"Benchmark anomaly {i}",
            method=DetectionMethod.RULE_BASED,
            detected_at=now,
        )
        anomalies.append(anom)
    store.anomalies[sess_id] = anomalies

    # Populate 50 incidents
    incidents = []
    for i in range(50):
        inc = Incident(
            id=f"inc-b-{i}",
            anomaly_id=f"anom-b-{i}",
            session_id=sess_id,
            category=IncidentCategory.INTRUSION_ATTEMPT,
            severity=SeverityLevel.HIGH,
            title=f"Benchmark Incident {i}",
            description=f"Benchmark incident description {i}",
            root_cause_hypothesis=f"Root cause {i}",
            potential_impact=f"Impact {i}",
            first_seen=now,
            last_seen=now,
            status=IncidentStatus.INVESTIGATING,
        )
        incidents.append(inc)
    store.incidents[sess_id] = incidents

    # Populate 20 attack chains
    chains = []
    for i in range(20):
        chain = AttackChain(
            id=f"chain-b-{i}",
            session_id=sess_id,
            title=f"Benchmark Chain {i}",
            summary=f"Summary for chain {i}",
            severity="CRITICAL",
            confidence_score=0.9,
            first_seen=now,
            last_seen=now,
            status=ChainStatus.CONFIRMED,
            potential_impact=f"Potential impact {i}",
            correlation_explanation=f"Explanation {i}",
            associated_anomaly_ids=[f"anom-b-{i}"],
            associated_incident_ids=[f"inc-b-{i}"],
            events=[
                ChainLinkEvent(
                    id=f"link-b-{i}",
                    log_entry_id=f"evt-b-{i}",
                    timestamp=now,
                    stage=AttackStage.INITIAL_ACCESS,
                    is_confirmed=True,
                    correlation_reason=f"Matched IOC {i}",
                    raw_log=f"Raw log {i}",
                    message=f"Message {i}",
                )
            ],
        )
        chains.append(chain)
    store.attack_chains[sess_id] = chains

    # Prepare IOC and Assessment
    ev = IOCEvidence(
        event_id="evt-b-0",
        session_id=sess_id,
        timestamp=now,
        raw_value="185.220.101.5",
        source_field="source_ip",
        line_number=101,
    )
    ioc = IOC(
        id="ioc-bench-target",
        ioc_type=IOCType.IPV4,
        raw_value="185.220.101.5",
        normalized_value="185.220.101.5",
        status=IOCStatus.UNDER_REVIEW,
        evidence_references=[ev],
        source_sessions=[sess_id],
        associated_anomaly_ids=["anom-b-0"],
        associated_incident_ids=["inc-b-0"],
    )
    ioc_repo.add_ioc(ioc)

    assessment = ThreatAssessment(
        ioc_id=ioc.id,
        ioc_type=ioc.ioc_type,
        ioc_value=ioc.raw_value,
        normalized_value=ioc.normalized_value,
        threat_score=92.0,
        confidence=0.95,
        severity=ThreatSeverity.CRITICAL,
        status=ThreatIntelStatus.MALICIOUS,
    )

    corr_latencies = []
    context_latencies = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = engine.correlate_ioc(ioc, threat_assessment=assessment)
        corr_latencies.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        _ = engine.build_unified_context(ioc, threat_assessment=assessment)
        context_latencies.append((time.perf_counter() - t1) * 1000.0)

    corr_stats = _percentiles(corr_latencies)
    ctx_stats = _percentiles(context_latencies)

    print(f"Correlation   | Avg: {corr_stats['avg']:.4f} ms | Med: {corr_stats['median']:.4f} ms | p95: {corr_stats['p95']:.4f} ms | p99: {corr_stats['p99']:.4f} ms")
    print(f"Unified Ctx   | Avg: {ctx_stats['avg']:.4f} ms | Med: {ctx_stats['median']:.4f} ms | p95: {ctx_stats['p95']:.4f} ms | p99: {ctx_stats['p99']:.4f} ms")

    return {"correlation": corr_stats, "unified_context": ctx_stats}


def run_full_benchmark():
    print("=" * 70)
    print("MICHAEL – THE GUARDIAN AI")
    print("PHASE 4.2B.6 THREAT INTELLIGENCE PERFORMANCE BENCHMARK")
    print("=" * 70)

    start = time.perf_counter()
    extract_res = benchmark_ioc_extraction()
    norm_res = benchmark_normalization_and_validation()
    rep_res = benchmark_reputation_engine()
    corr_res = benchmark_correlation_and_unified_context()
    total_sec = time.perf_counter() - start

    print("\n" + "=" * 70)
    print(f"BENCHMARK COMPLETE (Total duration: {total_sec:.2f} s)")
    print("=" * 70)


if __name__ == "__main__":
    run_full_benchmark()

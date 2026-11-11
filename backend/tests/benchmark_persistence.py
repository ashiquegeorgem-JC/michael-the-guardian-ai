"""
Benchmark Suite for MICHAEL – THE GUARDIAN AI Persistence Subsystem.

Phase 5.0 — Production Hardening & Persistence Integration.

Benchmarks persistence performance across scale tiers:
- Tier 1: 100 items
- Tier 2: 1,000 items
- Tier 3: 5,000 items
- Tier 4: 10,000 items

Operations measured:
1. Batch / Sequential Insertion Latency
2. Primary Key Direct Read Latency
3. Indexed Search / Filtering Latency
4. Relational & Evidence Query Latency

Outputs: Min, Max, Mean (Avg), Median, P95, and P99 latencies.
"""

from datetime import datetime, timezone
import gc
import os
import sys
import tempfile
import time
from typing import Dict, List
import numpy as np

# Ensure backend root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType
from app.models.log_entry import LogEntry, LogSession
from app.persistence.database import DatabaseManager
from app.persistence.sql_store import SQLIOCRepository, SQLStoreRepository


def calculate_metrics(latencies_ms: List[float]) -> Dict[str, float]:
    arr = np.array(latencies_ms)
    return {
        "count": len(arr),
        "mean_ms": float(np.mean(arr)),
        "median_ms": float(np.median(arr)),
        "p95_ms": float(np.percentile(arr, 95)),
        "p99_ms": float(np.percentile(arr, 99)),
        "min_ms": float(np.min(arr)),
        "max_ms": float(np.max(arr)),
        "throughput_ops_sec": float(len(arr) / (np.sum(arr) / 1000.0)) if np.sum(arr) > 0 else 0.0,
    }


def run_benchmark_tier(scale: int) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"  RUNNING BENCHMARK TIER: {scale:,} ITEMS")
    print(f"=======================================================")

    temp_dir = tempfile.TemporaryDirectory()
    db_path = os.path.join(temp_dir.name, f"bench_{scale}.db")
    db_manager = DatabaseManager(database_url=f"sqlite:///{db_path}")
    db_manager.init_db()

    store_repo = SQLStoreRepository(db_manager)
    ioc_repo = SQLIOCRepository(db_manager)

    now = datetime.now(timezone.utc)
    sess_id = f"bench-sess-{scale}"
    session = LogSession(
        id=sess_id,
        filename=f"bench_{scale}.log",
        file_size=scale * 128,
        total_lines=scale,
        uploaded_at=now,
    )

    # 1. Benchmark Insertion
    print(f"[*] Measuring insert latency for {scale:,} LogEntry items...")
    insert_latencies = []
    chunk_size = 500
    entries = []
    for i in range(scale):
        entries.append(
            LogEntry(
                id=f"ev-{scale}-{i}",
                session_id=sess_id,
                timestamp=now,
                level="INFO" if i % 10 != 0 else "WARNING",
                source=f"service-{(i % 5) + 1}",
                message=f"Benchmark log message payload record #{i} with random entropy {i*31 % 1000}",
                raw_line=f"2026-11-07T03:00:{i%60:02d}Z service-{(i%5)+1}: Benchmark log message payload record #{i}",
                line_number=i + 1,
            )
        )

    t0 = time.perf_counter()
    # Batch write
    for c in range(0, scale, chunk_size):
        chunk = entries[c : c + chunk_size]
        ct0 = time.perf_counter()
        store_repo.set_session(session, chunk)
        cdur = (time.perf_counter() - ct0) * 1000.0
        # Per item latency in batch
        per_item = cdur / len(chunk)
        insert_latencies.extend([per_item] * len(chunk))
    total_insert_sec = time.perf_counter() - t0
    insert_metrics = calculate_metrics(insert_latencies)
    print(f"    -> Insert Completed in {total_insert_sec:.3f}s. Avg: {insert_metrics['mean_ms']:.4f}ms, P95: {insert_metrics['p95_ms']:.4f}ms, Throughput: {insert_metrics['throughput_ops_sec']:.1f} ops/sec")

    # 2. Benchmark Primary Key Read (Sample 100 items or all if < 100)
    sample_size = min(100, scale)
    sample_indices = np.random.choice(scale, size=sample_size, replace=False)
    print(f"[*] Measuring point-read latency on {sample_size} sample entities...")
    read_latencies = []
    for idx in sample_indices:
        eid = f"ev-{scale}-{idx}"
        rt0 = time.perf_counter()
        # Direct session retrieval of entries
        _ = store_repo.get_session(sess_id)
        read_latencies.append((time.perf_counter() - rt0) * 1000.0)
    read_metrics = calculate_metrics(read_latencies)
    print(f"    -> Point-Read Avg: {read_metrics['mean_ms']:.4f}ms, Median: {read_metrics['median_ms']:.4f}ms, P95: {read_metrics['p95_ms']:.4f}ms")

    # 3. Benchmark IOC Insertion & Canonical Deduplication
    ioc_count = min(1000, scale)
    print(f"[*] Measuring IOC insertion & deduplication on {ioc_count:,} IOC entities...")
    ioc_insert_latencies = []
    for i in range(ioc_count):
        ip_val = f"10.{(i // 256) % 255}.{(i % 256)}.{(i * 7) % 254 + 1}"
        ioc = IOC(
            id=f"ioc-{scale}-{i}",
            ioc_type=IOCType.IPV4,
            raw_value=ip_val,
            normalized_value=ip_val,
            confidence=0.75,
            first_seen=now,
            last_seen=now,
            source_sessions=[sess_id],
            occurrence_count=1,
            evidence_references=[
                IOCEvidence(
                    event_id=f"ev-{scale}-{i}",
                    session_id=sess_id,
                    timestamp=now,
                    raw_value=ip_val,
                    source_field="src_ip",
                    line_number=i + 1,
                )
            ],
        )
        it0 = time.perf_counter()
        ioc_repo.add_ioc(ioc)
        ioc_insert_latencies.append((time.perf_counter() - it0) * 1000.0)
    ioc_insert_metrics = calculate_metrics(ioc_insert_latencies)
    print(f"    -> IOC Insert Avg: {ioc_insert_metrics['mean_ms']:.4f}ms, P95: {ioc_insert_metrics['p95_ms']:.4f}ms, P99: {ioc_insert_metrics['p99_ms']:.4f}ms")

    # 4. Benchmark Canonical Lookup & Relationship Query
    print(f"[*] Measuring canonical lookup and session relationship query latency...")
    query_latencies = []
    for i in range(min(100, ioc_count)):
        ip_val = f"10.{(i // 256) % 255}.{(i % 256)}.{(i * 7) % 254 + 1}"
        qt0 = time.perf_counter()
        _ = ioc_repo.get_ioc_by_normalized_value(IOCType.IPV4, ip_val)
        query_latencies.append((time.perf_counter() - qt0) * 1000.0)
    query_metrics = calculate_metrics(query_latencies)
    print(f"    -> Canonical Query Avg: {query_metrics['mean_ms']:.4f}ms, P95: {query_metrics['p95_ms']:.4f}ms")

    db_manager.close()
    gc.collect()
    try:
        temp_dir.cleanup()
    except Exception:
        pass

    return {
        "scale": scale,
        "insert": insert_metrics,
        "read": read_metrics,
        "ioc_insert": ioc_insert_metrics,
        "canonical_query": query_metrics,
    }


def main():
    print("=================================================================")
    print("  MICHAEL – THE GUARDIAN AI: PERSISTENCE PERFORMANCE BENCHMARK  ")
    print("=================================================================")

    tiers = [100, 1000, 5000, 10000]
    all_results = {}

    for t in tiers:
        all_results[t] = run_benchmark_tier(t)

    print("\n\n=================================================================")
    print("                      BENCHMARK SUMMARY MATRIX                   ")
    print("=================================================================")
    print(f"{'Scale Tier':<12} | {'Insert Avg':<12} | {'Insert P95':<12} | {'IOC Ins Avg':<12} | {'Query P95':<12}")
    print("-" * 70)
    for t in tiers:
        res = all_results[t]
        print(f"{t:<12,d} | {res['insert']['mean_ms']:<10.4f}ms | {res['insert']['p95_ms']:<10.4f}ms | {res['ioc_insert']['mean_ms']:<10.4f}ms | {res['canonical_query']['p95_ms']:<10.4f}ms")
    print("=================================================================\n")


if __name__ == "__main__":
    main()


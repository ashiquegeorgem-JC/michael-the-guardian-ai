"""
Phase 3 Temporal Dataset Generator
====================================
Generates synthetic log datasets with realistic temporal bursts and spike patterns
specifically designed to evaluate the Temporal Behaviour Intelligence Engine.

Categories (with non-overlapping IP spaces and time horizons):
  - Normal baseline traffic (50 logs)
  - SSH brute-force burst (30 logs, tight 10s windows)
  - HTTP flood / DDoS spike (25 logs, rapid burst)
  - SQL injection with 4xx/5xx spike (20 logs)
  - Outbound C2 connection burst (15 logs)
  - Auth anomaly pattern shift (20 logs)
  - Database connection spike (15 logs)
  - Resource exhaustion burst (15 logs)
  - Traffic spike – previously unseen patterns (20 logs)
  - HTTP error-rate surge (20 logs)
"""

import os
import csv
import random
from datetime import datetime, timezone, timedelta

random.seed(42)

BASE_DIR  = os.path.dirname(__file__)
TRAIN_DIR = BASE_DIR
TEST_DIR  = BASE_DIR

# ── IP spaces ──────────────────────────────────────────────────────────────────
NORMAL_IPS        = [f"10.0.{i}.{j}" for i in range(1, 4)  for j in range(1, 8)]
BRUTE_FORCE_IPS   = [f"172.16.{i}.{j}" for i in range(5, 7)  for j in range(1, 6)]
HTTP_FLOOD_IPS    = [f"192.168.100.{j}" for j in range(50, 60)]
SQLI_IPS          = [f"203.0.113.{j}" for j in range(10, 16)]
OUTBOUND_IPS      = [f"10.99.{j}.1" for j in range(1, 6)]
AUTH_ANOMALY_IPS  = [f"198.51.100.{j}" for j in range(20, 28)]
DB_FAIL_IPS       = [f"10.10.5.{j}" for j in range(1, 6)]
RESOURCE_IPS      = [f"10.50.{j}.1" for j in range(1, 5)]
UNSEEN_IPS        = [f"172.31.{j}.99" for j in range(1, 6)]
HTTP_ERR_IPS      = [f"192.168.200.{j}" for j in range(1, 8)]

ENDPOINTS         = ["/api/v1/products", "/api/v1/users", "/api/v1/orders",
                     "/api/health", "/api/v1/search"]
ATTACK_ENDPOINTS  = ["/api/admin", "/api/v1/users/login", "/api/auth/token",
                     "/api/v1/reports/export"]
ERROR_ENDPOINTS   = ["/api/v1/checkout", "/api/v1/payment", "/api/v1/cart"]


def _ts(base: datetime, offset_sec: float) -> str:
    return (base + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_normal(base: datetime, n: int = 50):
    rows = []
    for i in range(n):
        ip  = random.choice(NORMAL_IPS)
        ep  = random.choice(ENDPOINTS)
        lat = random.randint(10, 120)
        rows.append({
            "timestamp": _ts(base, i * 3.5 + random.uniform(0, 1)),
            "level": "INFO",
            "source": "nginx",
            "message": f"{ip} GET {ep} HTTP/1.1 200 {lat}ms",
            "label": 0,
            "category": "normal",
        })
    return rows


def generate_ssh_brute_force(base: datetime, n: int = 30):
    """Tight burst: many failures in <10s window per IP."""
    rows = []
    ip = random.choice(BRUTE_FORCE_IPS)
    for i in range(n):
        # Cluster 5 failures per 10s window
        cluster = i // 5
        offset  = cluster * 12 + (i % 5) * 1.5 + random.uniform(0, 0.5)
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "WARNING" if i % 5 < 4 else "CRITICAL",
            "source": "sshd",
            "message": (
                f"Failed password for root from {ip} port {22000 + i} ssh2"
                if i % 5 < 4
                else f"Authentication failure: 5 bad passwords in 10s from {ip}"
            ),
            "label": 1,
            "category": "ssh_bruteforce",
        })
    return rows


def generate_http_flood(base: datetime, n: int = 25):
    """Rapid burst: many requests in a single 30s window."""
    rows = []
    ip = random.choice(HTTP_FLOOD_IPS)
    ep = random.choice(ATTACK_ENDPOINTS)
    for i in range(n):
        offset = i * 1.0 + random.uniform(0, 0.2)  # tight 25s burst
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "WARNING",
            "source": "nginx",
            "message": f"{ip} GET {ep} HTTP/1.1 429 Too Many Requests",
            "label": 1,
            "category": "http_flood",
        })
    return rows


def generate_sqli(base: datetime, n: int = 20):
    """SQL injection with 4xx/5xx spikes."""
    rows = []
    ip = random.choice(SQLI_IPS)
    for i in range(n):
        offset = i * 2.5 + random.uniform(0, 0.5)
        is_err = i % 3 == 0
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "ERROR" if is_err else "WARNING",
            "source": "waf-guard",
            "message": (
                f"{ip} GET /api/v1/users?id=1%27+UNION+SELECT+null,password_hash+FROM+users-- "
                f"{'500' if is_err else '400'}"
                if i % 2 == 0
                else f"SQL Injection Pattern matched: Rule ID 942100 from {ip}"
            ),
            "label": 1,
            "category": "sql_injection",
        })
    return rows


def generate_outbound_c2(base: datetime, n: int = 15):
    """Suspicious outbound C2 connections in a burst."""
    rows = []
    ip = random.choice(OUTBOUND_IPS)
    c2 = "185.220.101.5"
    for i in range(n):
        port = random.randint(4000, 9000)
        offset = i * 4 + random.uniform(0, 1)
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "CRITICAL",
            "source": "net-sec",
            "message": f"outbound established {ip}:{random.randint(40000,60000)} -> {c2}:{port} bytes={random.randint(500,5000)}",
            "label": 1,
            "category": "c2_connection",
        })
    return rows


def generate_auth_anomaly(base: datetime, n: int = 20):
    """Unusual authentication pattern shift — off-hours logins."""
    rows = []
    for i in range(n):
        ip = random.choice(AUTH_ANOMALY_IPS)
        offset = i * 5 + random.uniform(0, 1)
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "WARNING",
            "source": "auth-service",
            "message": f"login failed for user admin from {ip}: bad password attempt {i+1}",
            "label": 1,
            "category": "auth_anomaly",
        })
    return rows


def generate_db_spike(base: datetime, n: int = 15):
    """Database connection spike."""
    rows = []
    ip = random.choice(DB_FAIL_IPS)
    for i in range(n):
        offset = i * 2 + random.uniform(0, 0.5)
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "ERROR",
            "source": "db-pool",
            "message": f"database connection pool exhausted: too many connections from {ip} (attempt {i+1})",
            "label": 1,
            "category": "db_failure",
        })
    return rows


def generate_resource_exhaustion(base: datetime, n: int = 15):
    """Resource exhaustion logs."""
    rows = []
    ip = random.choice(RESOURCE_IPS)
    for i in range(n):
        offset = i * 3 + random.uniform(0, 1)
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "CRITICAL",
            "source": "kernel",
            "message": f"Out of memory: Kill process {1000+i} (httpd) score {random.randint(800,999)} or sacrifice child",
            "label": 1,
            "category": "resource_exhaustion",
        })
    return rows


def generate_unseen_pattern(base: datetime, n: int = 20):
    """Previously unseen log message patterns that are volumetrically anomalous."""
    rows = []
    ip = random.choice(UNSEEN_IPS)
    for i in range(n):
        offset = i * 2 + random.uniform(0, 0.3)
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "WARNING",
            "source": "anomaly-probe",
            "message": (
                f"ZXQK-{random.randint(1000,9999)}: unrecognised protocol handshake "
                f"from {ip} seq={i} checksum=0x{random.randint(0, 0xFFFF):04X}"
            ),
            "label": 1,
            "category": "unseen_pattern",
        })
    return rows


def generate_http_error_surge(base: datetime, n: int = 20):
    """HTTP error-rate surge — >50% of requests are 4xx/5xx."""
    rows = []
    ip = random.choice(HTTP_ERR_IPS)
    ep = random.choice(ERROR_ENDPOINTS)
    for i in range(n):
        offset = i * 2.8 + random.uniform(0, 0.5)
        status = random.choice(["500", "503", "429", "400", "502"])
        rows.append({
            "timestamp": _ts(base, offset),
            "level": "ERROR",
            "source": "nginx",
            "message": f"{ip} POST {ep} HTTP/1.1 {status} upstream error latency=9999ms",
            "label": 1,
            "category": "http_error_surge",
        })
    return rows


def write_csv(rows, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "level", "source", "message", "label", "category"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Wrote {len(rows)} rows -> {path}")


def main():
    print("Generating Phase 3 Temporal Research Datasets...")

    # Training horizon: 2026-01-15 08:00 UTC
    train_base = datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    # Test horizon: 2026-02-20 14:00 UTC (fully separate from train)
    test_base  = datetime(2026, 2, 20, 14, 0, 0, tzinfo=timezone.utc)

    print("\n[TRAIN] Generating training dataset...")
    train_rows = []
    train_rows += generate_normal(train_base, n=50)
    train_rows += generate_ssh_brute_force(train_base + timedelta(minutes=5), n=30)
    train_rows += generate_http_flood(train_base + timedelta(minutes=15), n=25)
    train_rows += generate_sqli(train_base + timedelta(minutes=25), n=20)
    train_rows += generate_outbound_c2(train_base + timedelta(minutes=35), n=15)
    train_rows += generate_auth_anomaly(train_base + timedelta(minutes=45), n=20)
    train_rows += generate_db_spike(train_base + timedelta(minutes=55), n=15)
    train_rows += generate_resource_exhaustion(train_base + timedelta(minutes=65), n=15)
    train_rows.sort(key=lambda r: r["timestamp"])
    write_csv(train_rows, os.path.join(TRAIN_DIR, "temporal_train.csv"))

    print("\n[TEST] Generating held-out test dataset...")
    test_rows = []
    test_rows += generate_normal(test_base, n=50)
    test_rows += generate_ssh_brute_force(test_base + timedelta(minutes=5), n=30)
    test_rows += generate_http_flood(test_base + timedelta(minutes=15), n=25)
    test_rows += generate_sqli(test_base + timedelta(minutes=25), n=20)
    test_rows += generate_outbound_c2(test_base + timedelta(minutes=35), n=15)
    test_rows += generate_auth_anomaly(test_base + timedelta(minutes=45), n=20)
    test_rows += generate_db_spike(test_base + timedelta(minutes=55), n=15)
    test_rows += generate_resource_exhaustion(test_base + timedelta(minutes=65), n=15)
    test_rows += generate_unseen_pattern(test_base + timedelta(minutes=75), n=20)
    test_rows += generate_http_error_surge(test_base + timedelta(minutes=85), n=20)
    test_rows.sort(key=lambda r: r["timestamp"])
    write_csv(test_rows, os.path.join(TEST_DIR, "temporal_test.csv"))

    n_train_anom = sum(1 for r in train_rows if r["label"] == 1)
    n_test_anom  = sum(1 for r in test_rows  if r["label"] == 1)
    print(f"\nSummary:")
    print(f"  Train: {len(train_rows)} logs  |  Anomalous: {n_train_anom}  |  Normal: {len(train_rows) - n_train_anom}")
    print(f"  Test:  {len(test_rows)} logs   |  Anomalous: {n_test_anom}   |  Normal: {len(test_rows) - n_test_anom}")
    print("\nDone.")


if __name__ == "__main__":
    main()

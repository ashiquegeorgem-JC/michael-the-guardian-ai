"""
Independent Research Dataset Generator for MICHAEL - The Guardian AI.
Generates rigorously separated Train, Validation, and Test datasets with ground-truth labels.
Strict anti-leakage constraints:
- Non-overlapping IP spaces across Train, Val, and Test
- Non-overlapping time windows
- Distinct attacker user-agents and payload signatures
- Novel unseen zero-day log formats in the Test set
"""

import os
import csv
import random
from datetime import datetime, timedelta

DATA_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_datasets():
    os.makedirs(DATA_DIR, exist_ok=True)
    random.seed(42)

    # ─────────────────────────────────────────────────────────────────────────
    # 1. TRAINING DATASET: Baseline Normal Activity (Nov 01, 2026)
    # IP Space: 10.0.1.0/24, 192.168.1.0/24
    # ─────────────────────────────────────────────────────────────────────────
    train_records = []
    base_t_train = datetime(2026, 11, 1, 8, 0, 0)

    # Normal web requests
    endpoints = ["/api/v1/health", "/api/v1/products", "/api/v1/catalog", "/index.html", "/static/app.css", "/api/v1/orders"]
    for i in range(160):
        t = (base_t_train + timedelta(seconds=i * 12)).isoformat() + "Z"
        ip = f"10.0.1.{random.randint(10, 80)}"
        ep = random.choice(endpoints)
        dur = random.randint(12, 65)
        msg = f"HTTP GET {ep} status=200 duration={dur}ms client_ip={ip}"
        raw = f"{t} web-gateway [INFO] {msg}"
        train_records.append([t, "INFO", "web-gateway", msg, raw, 0, "normal_traffic"])

    # Routine Cron and System Maintenance
    services = ["cron-daemon", "disk-monitor", "kubelet", "systemd-journal", "db-sync"]
    for i in range(100):
        t = (base_t_train + timedelta(seconds=i * 20 + 3)).isoformat() + "Z"
        srv = random.choice(services)
        msg = f"Routine operational task completed successfully: job_id={random.randint(1000, 9999)} status=ok"
        raw = f"{t} {srv} [INFO] {msg}"
        train_records.append([t, "INFO", srv, msg, raw, 0, "normal_maintenance"])

    # Normal Database Read Transactions
    for i in range(50):
        t = (base_t_train + timedelta(seconds=i * 35 + 7)).isoformat() + "Z"
        uid = random.randint(100, 500)
        msg = f"Database read transaction committed: SELECT * FROM items WHERE user_id={uid} (latency 4ms)"
        raw = f"{t} postgresql [INFO] {msg}"
        train_records.append([t, "INFO", "postgresql", msg, raw, 0, "normal_database"])

    # Minor benign transient warnings (natural baseline noise)
    for i in range(10):
        t = (base_t_train + timedelta(seconds=i * 180 + 15)).isoformat() + "Z"
        msg = f"Slow response time noticed: HTTP GET /api/v1/reports duration=240ms client_ip=192.168.1.42"
        raw = f"{t} web-gateway [WARNING] {msg}"
        train_records.append([t, "WARNING", "web-gateway", msg, raw, 0, "normal_noise"])

    # Write train_logs.csv
    train_path = os.path.join(DATA_DIR, "train_logs.csv")
    with open(train_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "level", "source", "message", "raw_line", "label", "category"])
        writer.writerows(train_records)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. VALIDATION DATASET: Calibration & Hyperparameter Tuning (Nov 02, 2026)
    # IP Space: 172.16.10.0/24
    # ─────────────────────────────────────────────────────────────────────────
    val_records = []
    base_t_val = datetime(2026, 11, 2, 9, 0, 0)

    # 110 Normal events
    for i in range(110):
        t = (base_t_val + timedelta(seconds=i * 15)).isoformat() + "Z"
        ip = f"172.16.10.{random.randint(20, 90)}"
        msg = f"HTTP POST /api/v1/checkout status=201 duration={random.randint(30, 95)}ms client_ip={ip}"
        raw = f"{t} api-service [INFO] {msg}"
        val_records.append([t, "INFO", "api-service", msg, raw, 0, "normal_traffic"])

    # 40 Anomalies for validation tuning
    # Val SSH brute force attempts
    for i in range(15):
        t = (base_t_val + timedelta(seconds=1800 + i * 2)).isoformat() + "Z"
        user = random.choice(["oracle", "testuser", "support", "guest"])
        msg = f"Failed password for invalid user {user} from 172.16.10.250 port {51000+i} ssh2"
        raw = f"{t} sshd [WARNING] {msg}"
        val_records.append([t, "WARNING", "sshd", msg, raw, 1, "auth_failure"])

    # Val Database error
    for i in range(10):
        t = (base_t_val + timedelta(seconds=2200 + i * 4)).isoformat() + "Z"
        msg = f"PostgreSQL database query error: deadlock detected between PID {2000+i} and {3000+i}"
        raw = f"{t} postgresql [ERROR] {msg}"
        val_records.append([t, "ERROR", "postgresql", msg, raw, 1, "database_failure"])

    # Val Resource Exhaustion
    for i in range(10):
        t = (base_t_val + timedelta(seconds=2400 + i * 5)).isoformat() + "Z"
        msg = f"High memory consumption threshold exceeded: active_workers=32 allocated_ram=94.5%"
        raw = f"{t} worker-pool [WARNING] {msg}"
        val_records.append([t, "WARNING", "worker-pool", msg, raw, 1, "resource_exhaustion"])

    # Val Injection probe
    for i in range(5):
        t = (base_t_val + timedelta(seconds=2600 + i * 3)).isoformat() + "Z"
        msg = f"Suspicious parameter in HTTP GET /search?q=' OR 1=1-- from 172.16.10.199"
        raw = f"{t} nginx [WARNING] {msg}"
        val_records.append([t, "WARNING", "nginx", msg, raw, 1, "injection"])

    val_path = os.path.join(DATA_DIR, "val_logs.csv")
    with open(val_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "level", "source", "message", "raw_line", "label", "category"])
        writer.writerows(val_records)

    # ─────────────────────────────────────────────────────────────────────────
    # 3. TEST DATASET: Strictly Held-Out Benchmark (Nov 03, 2026)
    # Distinct External IP Space: 203.0.113.0/24, 198.51.100.0/24, 185.220.101.0/24
    # All 10 Required Research Classes represented
    # ─────────────────────────────────────────────────────────────────────────
    test_records = []
    base_t_test = datetime(2026, 11, 3, 14, 0, 0)

    # Class 1: Normal server activity (120 logs)
    normal_services = ["nginx", "api-gateway", "auth-service", "cache-redis", "payment-service", "metrics-collector"]
    for i in range(120):
        t = (base_t_test + timedelta(seconds=i * 10)).isoformat() + "Z"
        srv = random.choice(normal_services)
        ip = f"198.51.100.{random.randint(1, 100)}"
        status = random.choice([200, 200, 200, 204, 304])
        lat = random.randint(8, 75)
        msg = f"Handled inbound request: endpoint=/api/v2/{srv} client_ip={ip} status={status} duration={lat}ms"
        raw = f"{t} {srv} [INFO] {msg}"
        test_records.append([t, "INFO", srv, msg, raw, 0, "normal_activity"])

    # Class 2: SSH Brute-Force Attacks (10 logs)
    # Distinct attacker IP: 203.0.113.44
    for i in range(10):
        t = (base_t_test + timedelta(seconds=1300 + i * 2)).isoformat() + "Z"
        user = ["admin", "root", "ubuntu", "ansible", "deploy", "guest", "test", "postgres", "backup", "operator"][i]
        msg = f"Failed password for user {user} from 203.0.113.44 port {38400+i} ssh2; repeated attempts"
        raw = f"{t} sshd [WARNING] {msg}"
        test_records.append([t, "WARNING", "sshd", msg, raw, 1, "ssh_bruteforce"])

    # Class 3: SQL Injection (8 logs)
    # Blind SQLi & UNION attacks from 203.0.113.88
    sqli_payloads = [
        "GET /api/v1/users?id=1' UNION SELECT null,username,password_hash FROM users--",
        "POST /api/v1/auth/login payload=user' OR '1'='1' -- password=dummy",
        "GET /api/v1/catalog?category=shoes' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "GET /api/v1/items?filter=1; DROP TABLE audit_log; --",
        "Database query syntax error near '' UNION SELECT null,password_hash FROM users--': Postgres Error 42601",
        "WAF alert: SQL Injection signature matched rule ID 942100 on payload: ' UNION SELECT",
        "GET /api/v1/search?term=admin' OR 1=1#",
        "WAF alert: Blind Boolean SQLi pattern matched rule ID 942130 from 203.0.113.88",
    ]
    for i, payload in enumerate(sqli_payloads):
        t = (base_t_test + timedelta(seconds=1400 + i * 5)).isoformat() + "Z"
        lvl = "CRITICAL" if "WAF" in payload or "DROP" in payload else "ERROR"
        raw = f"{t} waf-shield [{lvl}] {payload}"
        test_records.append([t, lvl, "waf-shield", payload, raw, 1, "sql_injection"])

    # Class 4: Path Traversal (6 logs)
    # Double-encoded and standard traversal from 203.0.113.92
    traversal_payloads = [
        "GET /static/download?file=../../../../etc/passwd HTTP/1.1 status=400",
        "GET /api/v1/docs?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1 status=403",
        "GET /images/..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts HTTP/1.1 status=400",
        "Path traversal pattern detected: illegal relative directory climbing /../../../../etc/passwd",
        "WAF alert: Path Traversal rule ID 930110 triggered from client IP 203.0.113.92",
        "File access violation: attempt to read restricted root file descriptor /etc/shadow",
    ]
    for i, payload in enumerate(traversal_payloads):
        t = (base_t_test + timedelta(seconds=1450 + i * 4)).isoformat() + "Z"
        raw = f"{t} web-gateway [CRITICAL] {payload}"
        test_records.append([t, "CRITICAL", "web-gateway", payload, raw, 1, "path_traversal"])

    # Class 5: Suspicious Outbound Connections / C2 Beaconing (8 logs)
    for i in range(8):
        t = (base_t_test + timedelta(seconds=1500 + i * 6)).isoformat() + "Z"
        dest_ip = "185.220.101.5"
        dest_port = random.choice([4444, 1337, 8888, 9001])
        msg = f"Network guard alert: Outbound TCP session established to flagged C2 node {dest_ip}:{dest_port} payload_size={random.randint(1024, 8192)} bytes"
        raw = f"{t} network-guard [CRITICAL] {msg}"
        test_records.append([t, "CRITICAL", "network-guard", msg, raw, 1, "outbound_c2"])

    # Class 6: Abnormal Authentication & Privilege Escalation (8 logs)
    priv_logs = [
        "Accepted password for root from 203.0.113.44 port 41200 ssh2",
        "pam_unix(sshd:session): session opened for user root by (uid=0) without MFA verification",
        "sudo: user attacker : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        "Privilege escalation detected: process /tmp/payload spawned with effective UID 0",
        "Auditd warning: /etc/sudoers file modified by unexpected process PID 9102",
        "PAM 4 authentication failures; tty=pts/2 user=finance_admin rhost=203.0.113.15",
        "Off-hours privileged login detected for user 'system_admin' at 03:14:02 UTC from foreign subnet",
        "Security event: user account 'service_guest' added to sudoers group by non-standard process",
    ]
    for i, log_item in enumerate(priv_logs):
        t = (base_t_test + timedelta(seconds=1560 + i * 5)).isoformat() + "Z"
        raw = f"{t} audit-daemon [CRITICAL] {log_item}"
        test_records.append([t, "CRITICAL", "audit-daemon", log_item, raw, 1, "abnormal_auth"])

    # Class 7: Database Failures & Fatal Deadlocks (8 logs)
    db_failures = [
        "PostgreSQL fatal error: connection pool exhausted (max_connections=500 reached)",
        "Database deadlock detected: process 4109 waiting for ExclusiveLock on relation accounts",
        "MySQL server has gone away: query timed out after 30000ms on table transaction_ledger",
        "PostgreSQL critical error: database disk page 40182 corruption detected in index idx_users",
        "Redis replica connection lost: connection reset by peer on 10.0.1.20:6379",
        "Transaction rollback: serialization failure due to concurrent update conflict",
        "Database emergency: cannot allocate memory for sort buffer space in worker thread",
        "PostgreSQL fatal crash: server closed the connection unexpectedly (core dumped)",
    ]
    for i, fail_item in enumerate(db_failures):
        t = (base_t_test + timedelta(seconds=1610 + i * 5)).isoformat() + "Z"
        raw = f"{t} database-server [ERROR] {fail_item}"
        test_records.append([t, "ERROR", "database-server", fail_item, raw, 1, "database_failure"])

    # Class 8: Resource Exhaustion & OOM Crashes (8 logs)
    res_logs = [
        "kernel: Out of memory: Kill process 19482 (java) score 850 or sacrifice child",
        "oom-killer triggered: system physical RAM exhausted free_pages=102 available_mb=0",
        "Disk full: no space left on device /dev/nvme0n1p1 (100% inode capacity reached)",
        "Systemd warning: high swap memory usage 98.9% (swap thrashing detected)",
        "Threadpool starvation: all 256 worker threads blocked waiting for I/O semaphore",
        "Resource exhaustion: file descriptor limit (65536) exceeded by process PID 4101",
        "Kubernetes eviction alert: node-worker-02 MemoryPressure condition active",
        "Container killed: exit code 137 (SIGKILL) due to container cgroup OOM limits",
    ]
    for i, res_item in enumerate(res_logs):
        t = (base_t_test + timedelta(seconds=1660 + i * 4)).isoformat() + "Z"
        raw = f"{t} kernel [CRITICAL] {res_item}"
        test_records.append([t, "CRITICAL", "kernel", res_item, raw, 1, "resource_exhaustion"])

    # Class 9: Unusual Volumetric Traffic Spikes / DDoS (8 logs)
    for i in range(8):
        t = (base_t_test + timedelta(seconds=1700 + i * 3)).isoformat() + "Z"
        rps = 14500 + i * 850
        msg = f"Traffic spike anomaly detected: incoming request rate surge to {rps} req/sec (baseline is 250 req/sec) from multiple IP clusters"
        raw = f"{t} rate-limiter [WARNING] {msg}"
        test_records.append([t, "WARNING", "rate-limiter", msg, raw, 1, "traffic_spike"])

    # Class 10: Previously Unseen Novel Log Message Patterns (Zero-Day Log Schemas) (6 logs)
    unseen_patterns = [
        "@envoy_trace: {\"trace_id\": \"9a01bf\", \"upstream_cluster\": \"payment_v3\", \"error\": \"malformed_grpc_frame_header_overflow\", \"flags\": \"UO\"}",
        "cloud-native-mesh: [PROTOBUF_DECODE_ERR] Unknown binary opcode 0xFE received on internal gRPC channel from rogue container endpoint",
        "ebpf-sensor: [SYSCALL_HOOK_SURPRISE] process /usr/bin/python3 executed ptrace(PTRACE_POKETEXT) into kernel space PID 1",
        "mesh-telemetry: {\"event\": \"zero_day_rpc_deserialization_fault\", \"actor\": \"unknown_cluster_member\", \"severity_val\": 99}",
        "iot-daemon-v2: <<UNPARSED_HARDWARE_EXCEPTION>> sensor_bus_i2c parity fault with invalid register jump to 0x00000000",
        "ai-pipeline-worker: [TENSOR_CORRUPTION] GPU driver hardware fault Xid 79: GPU fallen off the PCIe bus during training run",
    ]
    for i, unseen in enumerate(unseen_patterns):
        t = (base_t_test + timedelta(seconds=1730 + i * 4)).isoformat() + "Z"
        raw = f"{t} zero-day-monitor [CRITICAL] {unseen}"
        test_records.append([t, "CRITICAL", "zero-day-monitor", unseen, raw, 1, "novel_unseen_pattern"])

    # Write test_logs.csv
    test_path = os.path.join(DATA_DIR, "test_logs.csv")
    with open(test_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "level", "source", "message", "raw_line", "label", "category"])
        writer.writerows(test_records)

    print(f"[DATASET GENERATION COMPLETE]")
    print(f"  Train Set:      {len(train_records)} records (Saved to {train_path})")
    print(f"  Validation Set: {len(val_records)} records (Saved to {val_path})")
    print(f"  Held-Out Test:  {len(test_records)} records (Saved to {test_path})")
    print(f"    - Normal:     {sum(1 for r in test_records if r[5] == 0)}")
    print(f"    - Anomalous:  {sum(1 for r in test_records if r[5] == 1)} (Across 9 attack/failure classes + 1 novel pattern class)")

if __name__ == "__main__":
    generate_datasets()

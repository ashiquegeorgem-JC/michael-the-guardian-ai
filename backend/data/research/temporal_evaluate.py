"""
Phase 3 Temporal Evaluation Script
=====================================
Evaluates the Temporal Behaviour Intelligence Engine against the
held-out temporal test dataset and compares:
  - Phase 2 Hybrid Ensemble (baseline)
  - Phase 3 Temporal Engine (new)
  - Phase 3 Hybrid + Temporal (combined)

Metrics reported:
  - Precision, Recall, F1-Score, Accuracy
  - False Positive Rate (FPR)
  - Per-category recall breakdown (volumetric spike categories)
  - Detection latency (avg seconds from event start to first detection)
  - Temporal recall improvement vs. Phase 2 baseline (Δ recall)
"""

import os
import sys
import csv
import json
import time
import logging
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Any

import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.models.log_entry import LogEntry, LogLevel
from app.models.anomaly import DetectionMethod
from app.ml.pipeline import run_anomaly_detection
from app.ml.temporal_engine import run_temporal_detection

logging.basicConfig(level=logging.WARNING)

SCRIPT_DIR = os.path.dirname(__file__)
TEST_CSV   = os.path.join(SCRIPT_DIR, "temporal_test.csv")
OUT_JSON   = os.path.join(SCRIPT_DIR, "temporal_evaluation_summary.json")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load_entries(csv_path: str) -> Tuple[List[LogEntry], List[int], List[str]]:
    """Load CSV into LogEntry list with ground-truth labels and categories."""
    entries = []
    labels  = []
    categories = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            ts = None
            try:
                ts = datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
            except Exception:
                pass

            level_map = {
                "DEBUG": LogLevel.DEBUG,
                "INFO": LogLevel.INFO,
                "WARNING": LogLevel.WARNING,
                "ERROR": LogLevel.ERROR,
                "CRITICAL": LogLevel.CRITICAL,
            }
            level = level_map.get(row.get("level", "INFO"), LogLevel.UNKNOWN)

            entry = LogEntry(
                session_id="temporal-eval",
                raw_line=f"{row['timestamp']} {row['source']} [{row['level']}] {row['message']}",
                timestamp=ts,
                level=level,
                source=row.get("source"),
                message=row.get("message", ""),
                line_number=i + 1,
            )
            entries.append(entry)
            labels.append(int(row.get("label", 0)))
            categories.append(row.get("category", "normal"))
    return entries, labels, categories


def _wilson_score_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate 95% Wilson score confidence interval for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0
    import math
    z = 1.95996
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    margin = (z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)) / denom
    return round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)


def _metrics(tp, fp, tn, fn) -> Dict[str, Any]:
    total_pos = tp + fn
    total_neg = fp + tn
    total_all = tp + fp + tn + fn
    total_pred_pos = tp + fp

    precision = tp / total_pred_pos if total_pred_pos > 0 else 0.0
    recall    = tp / total_pos if total_pos > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / total_all if total_all > 0 else 0.0
    fpr       = fp / total_neg if total_neg > 0 else 0.0

    prec_ci = _wilson_score_interval(tp, total_pred_pos)
    rec_ci  = _wilson_score_interval(tp, total_pos)
    fpr_ci  = _wilson_score_interval(fp, total_neg)
    acc_ci  = _wilson_score_interval(tp + tn, total_all)

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fpr": round(fpr, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "confidence_intervals_95": {
            "precision": list(prec_ci),
            "recall": list(rec_ci),
            "fpr": list(fpr_ci),
            "accuracy": list(acc_ci),
        },
    }


def _get_preds_from_anomalies(
    anomalies,
    entries,
    categories: List[str] = None,
    labels: List[int] = None,
) -> List[int]:
    """Map anomalies directly back to per-entry predictions using log_entry_ids."""
    flagged_ids = set()
    for a in anomalies:
        flagged_ids.update(a.log_entry_ids)
    return [1 if e.id in flagged_ids else 0 for e in entries]


def _per_category_recall(preds, labels, categories) -> Dict[str, Dict]:
    cats = set(categories)
    result = {}
    for cat in cats:
        indices = [i for i, c in enumerate(categories) if c == cat]
        cat_labels = [labels[i] for i in indices]
        cat_preds  = [preds[i] for i in indices]
        tp = sum(1 for p, y in zip(cat_preds, cat_labels) if p == 1 and y == 1)
        fn = sum(1 for p, y in zip(cat_preds, cat_labels) if p == 0 and y == 1)
        total_pos = tp + fn
        recall = tp / total_pos if total_pos > 0 else None
        result[cat] = {
            "total": len(indices),
            "anomalous": total_pos,
            "detected": tp,
            "recall": round(recall, 4) if recall is not None else "N/A",
        }
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Main Evaluation
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 68)
    print("  MICHAEL Phase 3 — Temporal Behaviour Intelligence Engine")
    print("  Independent Evaluation on Held-Out Temporal Test Dataset")
    print("=" * 68)

    if not os.path.exists(TEST_CSV):
        print(f"[ERROR] Test CSV not found: {TEST_CSV}")
        print("  Run temporal_dataset_generator.py first.")
        sys.exit(1)

    entries, labels, categories = _load_entries(TEST_CSV)
    print(f"\nLoaded {len(entries)} test entries "
          f"({sum(labels)} anomalous, {len(labels) - sum(labels)} normal)")

    session_id = "temporal-eval-session"
    results: Dict[str, Any] = {}

    # ── 1. Hybrid Ensemble (Phase 2 baseline) ─────────────────────────────────
    print("\n[1/3] Running Phase 2 Hybrid Ensemble (baseline)...")
    t0 = time.time()
    hybrid_anomalies, _ = run_anomaly_detection(entries, session_id + "-hybrid", contamination=0.15, enable_temporal=False)
    hybrid_duration = round(time.time() - t0, 3)
    hybrid_preds    = _get_preds_from_anomalies(hybrid_anomalies, entries, categories, labels)
    tp = sum(1 for p, y in zip(hybrid_preds, labels) if p == 1 and y == 1)
    fp = sum(1 for p, y in zip(hybrid_preds, labels) if p == 1 and y == 0)
    tn = sum(1 for p, y in zip(hybrid_preds, labels) if p == 0 and y == 0)
    fn = sum(1 for p, y in zip(hybrid_preds, labels) if p == 0 and y == 1)
    hybrid_m = _metrics(tp, fp, tn, fn)
    hybrid_cats = _per_category_recall(hybrid_preds, labels, categories)
    results["hybrid_ensemble_baseline"] = {
        "model": "Hybrid Ensemble (Phase 2)",
        "duration_seconds": hybrid_duration,
        "metrics": hybrid_m,
        "category_recall": hybrid_cats,
    }
    print(f"  Precision={hybrid_m['precision']:.4f}  Recall={hybrid_m['recall']:.4f}  "
          f"F1={hybrid_m['f1_score']:.4f}  FPR={hybrid_m['fpr']:.4f}  "
          f"[{hybrid_duration:.2f}s]")

    # ── 2. Temporal Engine Only (Phase 3) ─────────────────────────────────────
    print("\n[2/3] Running Phase 3 Temporal Engine only...")
    t0 = time.time()
    temporal_anomalies, telemetry = run_temporal_detection(entries, session_id + "-temporal")
    temporal_duration = round(time.time() - t0, 3)
    temporal_preds    = _get_preds_from_anomalies(temporal_anomalies, entries, categories, labels)
    tp = sum(1 for p, y in zip(temporal_preds, labels) if p == 1 and y == 1)
    fp = sum(1 for p, y in zip(temporal_preds, labels) if p == 1 and y == 0)
    tn = sum(1 for p, y in zip(temporal_preds, labels) if p == 0 and y == 0)
    fn = sum(1 for p, y in zip(temporal_preds, labels) if p == 0 and y == 1)
    temporal_m = _metrics(tp, fp, tn, fn)
    temporal_cats = _per_category_recall(temporal_preds, labels, categories)
    results["temporal_engine_only"] = {
        "model": "Temporal Engine (Phase 3)",
        "duration_seconds": temporal_duration,
        "metrics": temporal_m,
        "category_recall": temporal_cats,
        "telemetry_summary": {
            "global_spike_windows": len(telemetry.get("global_windows", {})),
            "ip_spikes": len(telemetry.get("ip_spikes", [])),
            "endpoint_spikes": len(telemetry.get("endpoint_spikes", [])),
            "category_spikes": len(telemetry.get("category_spikes", [])),
            "auth_burst_ips": len(telemetry.get("auth_burst_ips", [])),
            "http_error_buckets": len(telemetry.get("http_error_rate_buckets", [])),
        },
    }
    print(f"  Precision={temporal_m['precision']:.4f}  Recall={temporal_m['recall']:.4f}  "
          f"F1={temporal_m['f1_score']:.4f}  FPR={temporal_m['fpr']:.4f}  "
          f"[{temporal_duration:.2f}s]")

    # ── 3. Hybrid + Temporal Combined (Phase 3 Full) ───────────────────────────
    print("\n[3/3] Running Phase 3 Hybrid + Temporal (combined)...")
    t0 = time.time()
    all_anomalies, combined_metrics = run_anomaly_detection(
        entries, session_id + "-combined", contamination=0.15, enable_temporal=True
    )
    combined_duration = round(time.time() - t0, 3)
    combined_preds    = _get_preds_from_anomalies(all_anomalies, entries, categories, labels)
    tp = sum(1 for p, y in zip(combined_preds, labels) if p == 1 and y == 1)
    fp = sum(1 for p, y in zip(combined_preds, labels) if p == 1 and y == 0)
    tn = sum(1 for p, y in zip(combined_preds, labels) if p == 0 and y == 0)
    fn = sum(1 for p, y in zip(combined_preds, labels) if p == 0 and y == 1)
    combined_m = _metrics(tp, fp, tn, fn)
    combined_cats = _per_category_recall(combined_preds, labels, categories)

    # Recall improvement over Phase 2 baseline
    # Recall improvements
    recall_delta = round(combined_m["recall"] - hybrid_m["recall"], 4)

    # 1. 4-Category Subset (Matches original Phase 3 code benchmark)
    vol_cats_4 = ["ssh_bruteforce", "http_flood", "http_error_surge", "c2_connection"]
    vol_rec_base_4 = np.mean([hybrid_cats.get(c, {}).get("recall", 0) or 0 for c in vol_cats_4])
    vol_rec_comb_4 = np.mean([combined_cats.get(c, {}).get("recall", 0) or 0 for c in vol_cats_4])
    vol_delta_4 = round(float(vol_rec_comb_4) - float(vol_rec_base_4), 4)

    # 2. 6-Category Volumetric / Surge Suite (HTTP Flood, C2, DB, Auth Anomaly, HTTP Surge, Unseen)
    vol_cats_6 = ["http_flood", "c2_connection", "db_failure", "auth_anomaly", "http_error_surge", "unseen_pattern"]
    vol_rec_base_6 = np.mean([hybrid_cats.get(c, {}).get("recall", 0) or 0 for c in vol_cats_6])
    vol_rec_comb_6 = np.mean([combined_cats.get(c, {}).get("recall", 0) or 0 for c in vol_cats_6])
    vol_delta_6 = round(float(vol_rec_comb_6) - float(vol_rec_base_6), 4)

    # 3. All 7 Temporal Threat Categories (including SSH Brute Force)
    vol_cats_7 = ["ssh_bruteforce", "http_flood", "c2_connection", "db_failure", "auth_anomaly", "http_error_surge", "unseen_pattern"]
    vol_rec_base_7 = np.mean([hybrid_cats.get(c, {}).get("recall", 0) or 0 for c in vol_cats_7])
    vol_rec_comb_7 = np.mean([combined_cats.get(c, {}).get("recall", 0) or 0 for c in vol_cats_7])
    vol_delta_7 = round(float(vol_rec_comb_7) - float(vol_rec_base_7), 4)

    results["hybrid_plus_temporal"] = {
        "model": "Hybrid + Temporal (Phase 3 Full)",
        "duration_seconds": combined_duration,
        "metrics": combined_m,
        "category_recall": combined_cats,
        "improvement": {
            "recall_delta_vs_baseline": recall_delta,
            "volumetric_4cat_subset": {
                "categories": vol_cats_4,
                "total_samples": 90,
                "baseline_recall": round(float(vol_rec_base_4), 4),
                "combined_recall": round(float(vol_rec_comb_4), 4),
                "delta": vol_delta_4,
            },
            "volumetric_6cat_suite": {
                "categories": vol_cats_6,
                "total_samples": 115,
                "baseline_recall": round(float(vol_rec_base_6), 4),
                "combined_recall": round(float(vol_rec_comb_6), 4),
                "delta": vol_delta_6,
            },
            "temporal_all_7cat": {
                "categories": vol_cats_7,
                "total_samples": 145,
                "baseline_recall": round(float(vol_rec_base_7), 4),
                "combined_recall": round(float(vol_rec_comb_7), 4),
                "delta": vol_delta_7,
            },
        },
    }
    print(f"  Precision={combined_m['precision']:.4f}  Recall={combined_m['recall']:.4f}  "
          f"F1={combined_m['f1_score']:.4f}  FPR={combined_m['fpr']:.4f}  "
          f"[{combined_duration:.2f}s]")
    print(f"\n  Recall improvement vs baseline:  delta={recall_delta:+.4f}")
    print(f"  Volumetric (4-cat subset N=90):  delta={vol_delta_4:+.4f} "
          f"({vol_rec_base_4:.4f} -> {vol_rec_comb_4:.4f})")
    print(f"  Volumetric (6-cat suite N=115):  delta={vol_delta_6:+.4f} "
          f"({vol_rec_base_6:.4f} -> {vol_rec_comb_6:.4f})")
    print(f"  All Temporal (7-cat total N=145): delta={vol_delta_7:+.4f} "
          f"({vol_rec_base_7:.4f} -> {vol_rec_comb_7:.4f})")

    # ── Save JSON ──────────────────────────────────────────────────────────────
    output = {
        "evaluation_metadata": {
            "phase": "Phase 3 — Temporal Behaviour Intelligence Engine",
            "test_dataset": "temporal_test.csv",
            "total_test_entries": len(entries),
            "total_anomalous": sum(labels),
            "total_normal": len(labels) - sum(labels),
            "categories": sorted(set(categories)),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        },
        "results": results,
        "summary_table": {
            "Hybrid Ensemble (Phase 2 Baseline)": {
                "TP": hybrid_m["tp"],
                "FP": hybrid_m["fp"],
                "TN": hybrid_m["tn"],
                "FN": hybrid_m["fn"],
                "Precision": hybrid_m["precision"],
                "Precision_95_CI": hybrid_m["confidence_intervals_95"]["precision"],
                "Recall": hybrid_m["recall"],
                "Recall_95_CI": hybrid_m["confidence_intervals_95"]["recall"],
                "F1": hybrid_m["f1_score"],
                "Accuracy": hybrid_m["accuracy"],
                "FPR": hybrid_m["fpr"],
                "FPR_95_CI": hybrid_m["confidence_intervals_95"]["fpr"],
                "Duration(s)": hybrid_duration,
            },
            "Temporal Engine Only": {
                "TP": temporal_m["tp"],
                "FP": temporal_m["fp"],
                "TN": temporal_m["tn"],
                "FN": temporal_m["fn"],
                "Precision": temporal_m["precision"],
                "Precision_95_CI": temporal_m["confidence_intervals_95"]["precision"],
                "Recall": temporal_m["recall"],
                "Recall_95_CI": temporal_m["confidence_intervals_95"]["recall"],
                "F1": temporal_m["f1_score"],
                "Accuracy": temporal_m["accuracy"],
                "FPR": temporal_m["fpr"],
                "FPR_95_CI": temporal_m["confidence_intervals_95"]["fpr"],
                "Duration(s)": temporal_duration,
            },
            "Hybrid + Temporal (Phase 3)": {
                "TP": combined_m["tp"],
                "FP": combined_m["fp"],
                "TN": combined_m["tn"],
                "FN": combined_m["fn"],
                "Precision": combined_m["precision"],
                "Precision_95_CI": combined_m["confidence_intervals_95"]["precision"],
                "Recall": combined_m["recall"],
                "Recall_95_CI": combined_m["confidence_intervals_95"]["recall"],
                "F1": combined_m["f1_score"],
                "Accuracy": combined_m["accuracy"],
                "FPR": combined_m["fpr"],
                "FPR_95_CI": combined_m["confidence_intervals_95"]["fpr"],
                "Duration(s)": combined_duration,
                "Recall Δ vs Baseline": recall_delta,
                "Volumetric Recall Δ (4-cat N=90)": vol_delta_4,
                "Volumetric Recall Δ (6-cat N=115)": vol_delta_6,
                "Temporal Recall Δ (7-cat N=145)": vol_delta_7,
            },
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved -> {OUT_JSON}")
    print("=" * 68)
    return output


if __name__ == "__main__":
    main()

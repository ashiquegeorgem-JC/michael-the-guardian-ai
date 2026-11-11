"""
Phase 3.1 Audit Script: Independent Benchmark Integrity Verification
"""

import sys
sys.path.insert(0, '.')
import os
import csv
import time
import math
import tracemalloc
import platform
import psutil
from datetime import datetime, timezone
from collections import Counter, defaultdict
import numpy as np

from app.models.log_entry import LogEntry, LogLevel
from app.ml.pipeline import (
    run_anomaly_detection,
    run_isolation_forest,
    run_tfidf_analysis,
    run_statistical_detection,
    run_rule_based_detection,
)
from app.ml.temporal_engine import run_temporal_detection, TemporalEngine

TEST_CSV = 'data/research/temporal_test.csv'
TRAIN_CSV = 'data/research/temporal_train.csv'

# ─────────────────────────────────────────────────────────────────────────────
# 1. Dataset Loading & Integrity Check
# ─────────────────────────────────────────────────────────────────────────────

def load_data(filepath):
    entries = []
    labels = []
    categories = []
    ips = set()
    raw_lines = []
    timestamps = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            ts = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
            level = LogLevel(row['level']) if row['level'] in LogLevel.__members__.values() else LogLevel.INFO
            entry = LogEntry(
                session_id='audit',
                line_number=idx + 1,
                raw_line=f"{row['timestamp']} {row['source']} [{row['level']}] {row['message']}",
                timestamp=ts,
                level=level,
                source=row.get('source'),
                message=row['message'],
            )
            entries.append(entry)
            labels.append(int(row['label']))
            categories.append(row['category'])
            raw_lines.append(row['message'])
            timestamps.append(ts)
            
            # Extract IP
            import re
            m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', row['message'])
            if m:
                ips.add(m.group(0))
                
    return entries, labels, categories, ips, raw_lines, timestamps

test_entries, test_labels, test_cats, test_ips, test_raw, test_ts = load_data(TEST_CSV)
train_entries, train_labels, train_cats, train_ips, train_raw, train_ts = load_data(TRAIN_CSV)

print("=" * 70)
print("AUDIT SECTION 1 & 2: DATASET RECONSTRUCTION & CATEGORY COUNTS")
print("=" * 70)
print(f"Total Test Entries:  {len(test_entries)}")
print(f"Total Normal (y=0):  {test_labels.count(0)}")
print(f"Total Anomalous (y=1): {test_labels.count(1)}")

cat_counter = Counter(test_cats)
print("\nTest Dataset Category Distribution:")
for cat, cnt in sorted(cat_counter.items()):
    y_vals = [test_labels[i] for i, c in enumerate(test_cats) if c == cat]
    print(f"  {cat:22s}: total={cnt:3d} | anom={y_vals.count(1):3d} | norm={y_vals.count(0):3d}")

# ─────────────────────────────────────────────────────────────────────────────
# Reconstruct Predictions & Confusion Matrices
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_predictions(preds, labels):
    tp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 1)
    fp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 0)
    tn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 0)
    fn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 1)
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    acc  = (tp + tn) / len(labels) if len(labels) > 0 else 0.0
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Precision": prec, "Recall": rec, "F1": f1, "Accuracy": acc, "FPR": fpr
    }

def get_per_category(preds, labels, categories):
    res = {}
    for cat in sorted(set(categories)):
        idxs = [i for i, c in enumerate(categories) if c == cat]
        c_preds = [preds[i] for i in idxs]
        c_labels = [labels[i] for i in idxs]
        total = len(idxs)
        anom = sum(c_labels)
        detected = sum(1 for p, y in zip(c_preds, c_labels) if p == 1 and y == 1)
        rec = detected / anom if anom > 0 else None
        res[cat] = {"total": total, "anom": anom, "detected": detected, "recall": rec}
    return res

# 1. Baseline: Phase 2 Hybrid
t0 = time.time()
base_anomalies, _ = run_anomaly_detection(test_entries, 'audit-base', contamination=0.15, enable_temporal=False)
base_dur = time.time() - t0
base_ids = set()
for a in base_anomalies:
    base_ids.update(a.log_entry_ids)
base_preds = [1 if e.id in base_ids else 0 for e in test_entries]
base_cm = evaluate_predictions(base_preds, test_labels)
base_cats = get_per_category(base_preds, test_labels, test_cats)

# 2. Temporal Only
t0 = time.time()
temp_anomalies, temp_telemetry = run_temporal_detection(test_entries, 'audit-temp')
temp_dur = time.time() - t0
temp_ids = set()
for a in temp_anomalies:
    temp_ids.update(a.log_entry_ids)
temp_preds = [1 if e.id in temp_ids else 0 for e in test_entries]
temp_cm = evaluate_predictions(temp_preds, test_labels)
temp_cats = get_per_category(temp_preds, test_labels, test_cats)

# 3. Phase 3 Combined
t0 = time.time()
comb_anomalies, _ = run_anomaly_detection(test_entries, 'audit-comb', contamination=0.15, enable_temporal=True)
comb_dur = time.time() - t0
comb_ids = set()
for a in comb_anomalies:
    comb_ids.update(a.log_entry_ids)
comb_preds = [1 if e.id in comb_ids else 0 for e in test_entries]
comb_cm = evaluate_predictions(comb_preds, test_labels)
comb_cats = get_per_category(comb_preds, test_labels, test_cats)

print("\n" + "=" * 70)
print("CONFUSION MATRICES & METRICS RECONSTRUCTION")
print("=" * 70)

for name, cm, dur in [
    ("Phase 2 Baseline (No Temporal)", base_cm, base_dur),
    ("Phase 3 Temporal Engine Only", temp_cm, temp_dur),
    ("Phase 3 Combined Hybrid + Temporal", comb_cm, comb_dur),
]:
    print(f"\n--- {name} (latency: {dur:.3f}s) ---")
    print(f"  Confusion Matrix: TP={cm['TP']}, FP={cm['FP']}, TN={cm['TN']}, FN={cm['FN']}")
    print(f"  Precision: {cm['Precision']:.4f} ({cm['Precision']*100:.2f}%)")
    print(f"  Recall:    {cm['Recall']:.4f} ({cm['Recall']*100:.2f}%)")
    print(f"  F1-Score:  {cm['F1']:.4f}")
    print(f"  Accuracy:  {cm['Accuracy']:.4f} ({cm['Accuracy']*100:.2f}%)")
    print(f"  FPR:       {cm['FPR']:.4f} ({cm['FPR']*100:.2f}%)")

print("\n" + "=" * 70)
print("CATEGORY-LEVEL AUDIT & INVESTIGATION OF DISCREPANCY")
print("=" * 70)

print(f"{'Category':24s} | {'Anom':5s} | {'Base Detected':13s} | {'Temp Detected':13s} | {'Comb Detected':13s}")
print("-" * 75)
for cat in sorted(set(test_cats)):
    if cat == "normal": continue
    b_rec = f"{base_cats[cat]['detected']}/{base_cats[cat]['anom']} ({base_cats[cat]['recall']*100:.1f}%)"
    t_rec = f"{temp_cats[cat]['detected']}/{temp_cats[cat]['anom']} ({temp_cats[cat]['recall']*100:.1f}%)"
    c_rec = f"{comb_cats[cat]['detected']}/{comb_cats[cat]['anom']} ({comb_cats[cat]['recall']*100:.1f}%)"
    print(f"{cat:24s} | {base_cats[cat]['anom']:5d} | {b_rec:13s} | {t_rec:13s} | {c_rec:13s}")

# Detailed investigation of the 90 vs 115 vs 145 count discrepancy
code_vol_cats = ["ssh_bruteforce", "http_flood", "http_error_surge", "c2_connection"]
code_vol_count = sum(base_cats[c]['anom'] for c in code_vol_cats)
code_base_vol_rec = np.mean([base_cats[c]['recall'] for c in code_vol_cats])
code_comb_vol_rec = np.mean([comb_cats[c]['recall'] for c in code_vol_cats])

pure_vol_cats = ["http_flood", "c2_connection", "db_failure", "auth_anomaly", "http_error_surge", "unseen_pattern"]
pure_vol_count = sum(base_cats[c]['anom'] for c in pure_vol_cats)
pure_base_vol_rec = np.mean([base_cats[c]['recall'] for c in pure_vol_cats])
pure_comb_vol_rec = np.mean([comb_cats[c]['recall'] for c in pure_vol_cats])

all_temporal_cats = ["ssh_bruteforce", "http_flood", "c2_connection", "db_failure", "auth_anomaly", "http_error_surge", "unseen_pattern"]
all_temp_count = sum(base_cats[c]['anom'] for c in all_temporal_cats)
all_base_vol_rec = np.mean([base_cats[c]['recall'] for c in all_temporal_cats])
all_comb_vol_rec = np.mean([comb_cats[c]['recall'] for c in all_temporal_cats])

print("\nDiscrepancy Root Cause Analysis:")
print(f"1. Code Implementation in temporal_evaluate.py line 227:")
print(f"   volumetric_cats = {code_vol_cats}")
print(f"   Sum of anomalies in these 4 categories = {code_vol_count} (Matches reported '90')")
print(f"   Baseline average recall = {code_base_vol_rec:.4f} ({code_base_vol_rec*100:.1f}%)")
print(f"   Combined average recall = {code_comb_vol_rec:.4f} ({code_comb_vol_rec*100:.1f}%)")

print(f"\n2. Conceptual Volumetric/Burst Categories in Test Dataset:")
print(f"   Categories: {pure_vol_cats}")
print(f"   Sum of anomalies in these 6 categories = {pure_vol_count} (Matches user observation '115')")
print(f"   Baseline average recall = {pure_base_vol_rec:.4f} ({pure_base_vol_rec*100:.1f}%)")
print(f"   Combined average recall = {pure_comb_vol_rec:.4f} ({pure_comb_vol_rec*100:.1f}%)")

print(f"\n3. All 7 Temporal Threat Categories (including SSH brute force):")
print(f"   Categories: {all_temporal_cats}")
print(f"   Sum of anomalies in these 7 categories = {all_temp_count}")
print(f"   Baseline average recall = {all_base_vol_rec:.4f} ({all_base_vol_rec*100:.1f}%)")
print(f"   Combined average recall = {all_comb_vol_rec:.4f} ({all_comb_vol_rec*100:.1f}%)")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Data Leakage Audit
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("AUDIT SECTION 3: TEMPORAL DATA LEAKAGE AUDIT")
print("=" * 70)

print(f"Training Time Range: {min(train_ts).isoformat()} -> {max(train_ts).isoformat()}")
print(f"Testing Time Range:  {min(test_ts).isoformat()} -> {max(test_ts).isoformat()}")
time_delta_days = (min(test_ts) - max(train_ts)).total_seconds() / 86400.0
print(f"Time Gap between Train and Test: {time_delta_days:.1f} days")

ip_intersection = train_ips.intersection(test_ips)
print(f"Train IP count: {len(train_ips)}, Test IP count: {len(test_ips)}")
print(f"IP overlap between Train and Test: {len(ip_intersection)} IPs ({ip_intersection})")

raw_train_set = set(train_raw)
raw_test_set = set(test_raw)
raw_overlap = raw_train_set.intersection(raw_test_set)
print(f"Exact message overlap count: {len(raw_overlap)} out of {len(test_raw)} test logs")

# Check time sorting within test set (causality)
is_test_sorted = all(test_ts[i] <= test_ts[i+1] for i in range(len(test_ts)-1))
print(f"Test events strictly chronological: {is_test_sorted}")

# ─────────────────────────────────────────────────────────────────────────────
# 4. Latency, Cold/Warm Start & Memory Profiling
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("AUDIT SECTION 4: PERFORMANCE CLAIMS & BENCHMARKING")
print("=" * 70)

# Memory & Latency over varied N
test_sizes = [50, 100, 230]
# Generate larger synthetic batches by replication with time shift
if len(test_entries) >= 230:
    extra_entries = []
    base_t = test_ts[-1]
    for mult in [2, 5, 10, 20]:
        sz = 230 * mult
        test_sizes.append(sz)

print(f"System Environment:")
print(f"  OS: {platform.system()} {platform.release()} ({platform.version()})")
print(f"  Architecture: {platform.machine()}")
print(f"  Processor: {platform.processor()}")
print(f"  Logical CPU Cores: {psutil.cpu_count(logical=True)}")
print(f"  Total RAM: {psutil.virtual_memory().total / (1024**3):.2f} GB")
print(f"  Python Version: {platform.python_version()}")

# Latency vs Scale Benchmark
print("\nThroughput & Latency Scaling:")
print(f"{'Batch Size (N)':15s} | {'Temporal Only (ms)':20s} | {'Combined Pipeline (ms)':24s} | {'Peak Memory (MB)':18s}")
print("-" * 85)

for n in [50, 100, 230, 500, 1000, 2500, 5000]:
    # Construct entries of size n
    if n <= len(test_entries):
        sample = test_entries[:n]
    else:
        # Replicate with offset
        sample = []
        for i in range(n):
            src = test_entries[i % len(test_entries)]
            dt_offset = (i // len(test_entries)) * 3600
            new_ts = datetime.fromtimestamp(src.timestamp.timestamp() + dt_offset, tz=timezone.utc)
            sample.append(LogEntry(
                session_id=f"scale-{n}",
                line_number=i+1,
                raw_line=src.raw_line,
                timestamp=new_ts,
                level=src.level,
                source=src.source,
                message=src.message,
            ))
            
    tracemalloc.start()
    t0 = time.perf_counter()
    _, _ = run_temporal_detection(sample, f"scale-temp-{n}")
    t_temp = (time.perf_counter() - t0) * 1000.0
    
    t0 = time.perf_counter()
    _, _ = run_anomaly_detection(sample, f"scale-comb-{n}", contamination=0.15, enable_temporal=True)
    t_comb = (time.perf_counter() - t0) * 1000.0
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    print(f"{n:15d} | {t_temp:17.2f} ms | {t_comb:21.2f} ms | {peak_mem / (1024*1024):15.2f} MB")

# Cold start vs Warm start
print("\nCold Start vs Warm Start Latency (N=230):")
# Cold run
tracemalloc.start()
t0 = time.perf_counter()
_ = run_temporal_detection(test_entries, "cold")
cold_lat = (time.perf_counter() - t0) * 1000.0

warm_lats = []
for _ in range(10):
    t0 = time.perf_counter()
    _ = run_temporal_detection(test_entries, "warm")
    warm_lats.append((time.perf_counter() - t0) * 1000.0)
tracemalloc.stop()

print(f"  Cold-start Temporal: {cold_lat:.2f} ms")
print(f"  Warm-start Temporal (avg of 10 runs): {np.mean(warm_lats):.2f} ms ± {np.std(warm_lats):.2f} ms")

# ─────────────────────────────────────────────────────────────────────────────
# 5. Statistical Reliability & Confidence Intervals
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("AUDIT SECTION 5: STATISTICAL RELIABILITY & CONFIDENCE INTERVALS (95%)")
print("=" * 70)

def wilson_score_interval(k, n, confidence=0.95):
    """Wilson score confidence interval for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0
    z = 1.95996  # 95% confidence z-score
    p = k / n
    denominator = 1 + z**2 / n
    centre_adjusted_probability = (p + z**2 / (2 * n)) / denominator
    adjusted_std_error = (z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)) / denominator
    lower = max(0.0, centre_adjusted_probability - adjusted_std_error)
    upper = min(1.0, centre_adjusted_probability + adjusted_std_error)
    return lower, upper

print(f"{'Model':30s} | {'Metric':10s} | {'Point Est':10s} | {'95% CI':20s}")
print("-" * 75)

for model_name, cm in [
    ("Phase 2 Baseline", base_cm),
    ("Phase 3 Temporal Only", temp_cm),
    ("Phase 3 Combined Hybrid", comb_cm),
]:
    # Precision CI (k=TP, n=TP+FP)
    prec_lo, prec_hi = wilson_score_interval(cm["TP"], cm["TP"] + cm["FP"])
    # Recall CI (k=TP, n=TP+FN = 180)
    rec_lo, rec_hi = wilson_score_interval(cm["TP"], cm["TP"] + cm["FN"])
    # FPR CI (k=FP, n=FP+TN = 50)
    fpr_lo, fpr_hi = wilson_score_interval(cm["FP"], cm["FP"] + cm["TN"])
    # Accuracy CI (k=TP+TN, n=230)
    acc_lo, acc_hi = wilson_score_interval(cm["TP"] + cm["TN"], len(test_labels))
    
    print(f"{model_name:30s} | {'Precision':10s} | {cm['Precision']:9.4f}  | [{prec_lo:.4f}, {prec_hi:.4f}]")
    print(f"{'':30s} | {'Recall':10s} | {cm['Recall']:9.4f}  | [{rec_lo:.4f}, {rec_hi:.4f}]")
    print(f"{'':30s} | {'FPR':10s} | {cm['FPR']:9.4f}  | [{fpr_lo:.4f}, {fpr_hi:.4f}]")
    print(f"{'':30s} | {'Accuracy':10s} | {cm['Accuracy']:9.4f}  | [{acc_lo:.4f}, {acc_hi:.4f}]")
    print("-" * 75)

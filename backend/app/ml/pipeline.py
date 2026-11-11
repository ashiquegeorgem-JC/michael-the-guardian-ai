"""
Machine Learning Anomaly Detection Pipeline.

Methods:
1. Isolation Forest (unsupervised ML)
2. TF-IDF textual analysis (NLP-based)
3. Statistical detection (z-score, IQR)
4. Rule-based detection (known critical patterns)
"""

import re
import time
import uuid
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from typing import List, Dict, Tuple, Any, Optional

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from scipy import stats

from app.models.log_entry import LogEntry, LogLevel
from app.models.anomaly import Anomaly, SeverityLevel, DetectionMethod, ModelMetrics
from app.ml.temporal_engine import run_temporal_detection

logger = logging.getLogger("michael.ml")

# ──────────────────────────────────────────────────────────────────────────────
# Rule-based critical patterns
# ──────────────────────────────────────────────────────────────────────────────
CRITICAL_RULES = [
    {
        "pattern": re.compile(r"(failed\s+password|authentication\s+failure|invalid\s+user)", re.IGNORECASE),
        "reason": "Authentication failure detected",
        "category": "auth_failure",
        "base_severity": SeverityLevel.HIGH,
    },
    {
        "pattern": re.compile(r"(sql\s*injection|drop\s+table|union\s+select|xss|<script)", re.IGNORECASE),
        "reason": "Potential injection attack pattern",
        "category": "injection",
        "base_severity": SeverityLevel.CRITICAL,
    },
    {
        "pattern": re.compile(r"(segmentation\s+fault|segfault|core\s+dumped|kernel\s+panic)", re.IGNORECASE),
        "reason": "System crash or critical error",
        "category": "crash",
        "base_severity": SeverityLevel.CRITICAL,
    },
    {
        "pattern": re.compile(r"(out\s+of\s+memory|oom\s+killer|cannot\s+allocate|disk\s+full|no\s+space)", re.IGNORECASE),
        "reason": "Resource exhaustion detected",
        "category": "resource",
        "base_severity": SeverityLevel.HIGH,
    },
    {
        "pattern": re.compile(r"(privilege\s+escalat|sudo.*error|unauthorized.*root|permission\s+denied.*root)", re.IGNORECASE),
        "reason": "Privilege escalation attempt",
        "category": "privilege",
        "base_severity": SeverityLevel.CRITICAL,
    },
    {
        "pattern": re.compile(r"(port\s+scan|nmap|mass\s+scan|brute\s+force)", re.IGNORECASE),
        "reason": "Network scanning or brute-force activity",
        "category": "network_attack",
        "base_severity": SeverityLevel.HIGH,
    },
    {
        "pattern": re.compile(r"(malware|ransomware|trojan|rootkit|backdoor|exploit)", re.IGNORECASE),
        "reason": "Malware indicator detected",
        "category": "malware",
        "base_severity": SeverityLevel.CRITICAL,
    },
    {
        "pattern": re.compile(r"(connection\s+refused|timeout|connection\s+reset).*(\d+\s+time|\d+\s+attempt)", re.IGNORECASE),
        "reason": "Repeated connection failures",
        "category": "network_anomaly",
        "base_severity": SeverityLevel.MEDIUM,
    },
]


def score_to_severity(score: float) -> SeverityLevel:
    """Map anomaly score (0-1) to severity level."""
    if score >= 0.85:
        return SeverityLevel.CRITICAL
    elif score >= 0.65:
        return SeverityLevel.HIGH
    elif score >= 0.40:
        return SeverityLevel.MEDIUM
    else:
        return SeverityLevel.LOW


def _build_feature_dataframe(entries: List[LogEntry]) -> pd.DataFrame:
    """Build a numeric feature matrix from log entries."""
    records = []
    for e in entries:
        level_score = {
            LogLevel.DEBUG: 0,
            LogLevel.INFO: 1,
            LogLevel.WARNING: 2,
            LogLevel.ERROR: 3,
            LogLevel.CRITICAL: 4,
            LogLevel.UNKNOWN: 1,
        }.get(e.level, 1)

        msg = e.message or e.raw_line
        records.append({
            "level_score": level_score,
            "msg_length": len(msg),
            "num_digits": sum(c.isdigit() for c in msg),
            "num_special": sum(not c.isalnum() and not c.isspace() for c in msg),
            "has_ip": 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg) else 0,
            "has_url": 1 if re.search(r'https?://', msg) else 0,
            "has_error_word": 1 if re.search(r'\b(error|fail|exception|crash|deny)\b', msg, re.I) else 0,
            "hour": e.timestamp.hour if e.timestamp else 12,
        })
    return pd.DataFrame(records)


# ──────────────────────────────────────────────────────────────────────────────
# Detection Methods
# ──────────────────────────────────────────────────────────────────────────────

def run_isolation_forest(
    entries: List[LogEntry],
    contamination: float = 0.05,
) -> Tuple[List[int], np.ndarray, Dict[str, Any]]:
    """
    Apply Isolation Forest to numeric features extracted from log entries.
    Returns: (anomaly_indices, raw_scores, params)
    """
    if len(entries) < 10:
        return [], np.array([]), {}

    df = _build_feature_dataframe(entries)
    scaler = StandardScaler()
    X = scaler.fit_transform(df.values)

    clf = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    preds = clf.fit_predict(X)
    raw_scores = clf.decision_function(X)

    # Normalise scores to 0–1 (higher = more anomalous)
    norm_scores = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-10)

    anomaly_indices = [i for i, p in enumerate(preds) if p == -1]
    params = {
        "n_estimators": 100,
        "contamination": contamination,
        "n_features": df.shape[1],
        "feature_names": list(df.columns),
    }
    return anomaly_indices, norm_scores, params


def run_tfidf_analysis(
    entries: List[LogEntry],
    max_features: int = 500,
    top_k: int = 20,
) -> Tuple[List[int], np.ndarray, List[Dict[str, Any]]]:
    """
    Use TF-IDF to detect rare/unusual log messages.
    Returns: (anomaly_indices, scores, top_terms)
    """
    if len(entries) < 5:
        return [], np.array([]), []

    texts = [e.message or e.raw_line for e in entries]
    vectorizer = TfidfVectorizer(
        max_features=max_features,
        stop_words='english',
        ngram_range=(1, 2),
        min_df=1,
    )
    tfidf_matrix = vectorizer.fit_transform(texts)

    # Anomaly score = average TF-IDF across all terms (rare messages have high scores)
    scores = np.asarray(tfidf_matrix.mean(axis=1)).flatten()
    
    # Normalise
    if scores.max() > scores.min():
        norm_scores = (scores - scores.min()) / (scores.max() - scores.min())
    else:
        norm_scores = np.zeros_like(scores)

    # Flag top 5% as anomalies by TF-IDF rarity
    threshold = np.percentile(norm_scores, 95)
    anomaly_indices = [i for i, s in enumerate(norm_scores) if s >= threshold]

    # Top terms by TF-IDF weight
    feature_names = vectorizer.get_feature_names_out()
    mean_tfidf = np.asarray(tfidf_matrix.mean(axis=0)).flatten()
    top_idx = mean_tfidf.argsort()[-top_k:][::-1]
    top_terms = [
        {"term": feature_names[i], "score": float(mean_tfidf[i])}
        for i in top_idx
    ]

    return anomaly_indices, norm_scores, top_terms


def run_statistical_detection(
    entries: List[LogEntry],
) -> Tuple[List[int], np.ndarray]:
    """
    Z-score and IQR-based statistical anomaly detection on log volume bursts
    and message length outliers.
    """
    if len(entries) < 10:
        return [], np.array([])

    lengths = np.array([len(e.message or e.raw_line) for e in entries], dtype=float)
    z_scores = np.abs(stats.zscore(lengths))
    
    # IQR method
    q1, q3 = np.percentile(lengths, [25, 75])
    iqr = q3 - q1
    iqr_upper = q3 + 3.0 * iqr

    # Anomaly if z-score > 3 OR length > IQR upper bound
    anomaly_mask = (z_scores > 3) | (lengths > iqr_upper)
    anomaly_indices = [i for i, v in enumerate(anomaly_mask) if v]

    # Normalise z-scores for ranking
    norm_scores = np.clip(z_scores / (z_scores.max() + 1e-10), 0, 1)

    return anomaly_indices, norm_scores


def run_rule_based_detection(
    entries: List[LogEntry],
) -> List[Tuple[int, float, str, SeverityLevel]]:
    """
    Pattern-matching rule engine for known critical events.
    Returns list of (index, score, reason, severity).
    """
    results = []
    for i, entry in enumerate(entries):
        text = (entry.message or '') + ' ' + entry.raw_line
        for rule in CRITICAL_RULES:
            if rule["pattern"].search(text):
                severity = rule["base_severity"]
                # Escalate if also ERROR/CRITICAL level
                if entry.level in (LogLevel.CRITICAL, LogLevel.ERROR):
                    if severity == SeverityLevel.HIGH:
                        severity = SeverityLevel.CRITICAL
                score = {
                    SeverityLevel.CRITICAL: 0.95,
                    SeverityLevel.HIGH: 0.80,
                    SeverityLevel.MEDIUM: 0.60,
                    SeverityLevel.LOW: 0.40,
                }[severity]
                results.append((i, score, rule["reason"], severity))
                break  # One rule per entry
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Main Pipeline
# ──────────────────────────────────────────────────────────────────────────────

def run_anomaly_detection(
    entries: List[LogEntry],
    session_id: str,
    contamination: float = 0.05,
    enable_temporal: bool = True,
) -> Tuple[List[Anomaly], ModelMetrics]:
    """
    Run the full anomaly detection pipeline on a list of log entries.
    Combines all four methods and deduplicates results.
    """
    start_time = time.time()
    logger.info(f"Starting anomaly detection on {len(entries)} entries (session={session_id})")

    if not entries:
        return [], ModelMetrics(
            session_id=session_id,
            total_logs=0,
            anomalies_detected=0,
            contamination_rate=contamination,
            detection_methods=[],
            analysis_duration_seconds=0.0,
        )

    anomalies: List[Anomaly] = []
    seen_indices: Dict[int, Anomaly] = {}  # index → anomaly (for merging)

    # 1. Isolation Forest
    try:
        if_indices, if_scores, if_params = run_isolation_forest(entries, contamination)
        for idx in if_indices:
            score = float(if_scores[idx])
            entry = entries[idx]
            anomaly = Anomaly(
                session_id=session_id,
                log_entry_ids=[entry.id],
                score=score,
                severity=score_to_severity(score),
                reason=f"Isolation Forest detected anomalous feature pattern (score={score:.3f})",
                method=DetectionMethod.ISOLATION_FOREST,
                supporting_logs=[entry.raw_line],
                metadata={"feature_scores": if_params.get("feature_names", [])},
            )
            seen_indices[idx] = anomaly
            anomalies.append(anomaly)
        logger.info(f"Isolation Forest: {len(if_indices)} anomalies")
    except Exception as e:
        logger.error(f"Isolation Forest failed: {e}")
        if_params = {}

    # 2. TF-IDF
    try:
        tfidf_indices, tfidf_scores, top_terms = run_tfidf_analysis(entries)
        for idx in tfidf_indices:
            if idx in seen_indices:
                # Merge: boost score
                seen_indices[idx].score = min(1.0, seen_indices[idx].score + 0.1)
                seen_indices[idx].severity = score_to_severity(seen_indices[idx].score)
                seen_indices[idx].reason += " + Rare textual pattern (TF-IDF)"
                continue
            score = float(tfidf_scores[idx]) if idx < len(tfidf_scores) else 0.5
            entry = entries[idx]
            anomaly = Anomaly(
                session_id=session_id,
                log_entry_ids=[entry.id],
                score=score,
                severity=score_to_severity(score),
                reason=f"Rare log message pattern detected via TF-IDF analysis",
                method=DetectionMethod.TFIDF,
                supporting_logs=[entry.raw_line],
            )
            seen_indices[idx] = anomaly
            anomalies.append(anomaly)
        logger.info(f"TF-IDF: {len(tfidf_indices)} anomalies")
    except Exception as e:
        logger.error(f"TF-IDF failed: {e}")
        top_terms = []

    # 3. Statistical
    try:
        stat_indices, stat_scores = run_statistical_detection(entries)
        for idx in stat_indices:
            if idx in seen_indices:
                seen_indices[idx].score = min(1.0, seen_indices[idx].score + 0.05)
                continue
            score = float(stat_scores[idx]) if idx < len(stat_scores) else 0.5
            entry = entries[idx]
            anomaly = Anomaly(
                session_id=session_id,
                log_entry_ids=[entry.id],
                score=score,
                severity=score_to_severity(score),
                reason=f"Statistical outlier: message length exceeds 3σ boundary",
                method=DetectionMethod.STATISTICAL,
                supporting_logs=[entry.raw_line],
            )
            seen_indices[idx] = anomaly
            anomalies.append(anomaly)
        logger.info(f"Statistical: {len(stat_indices)} anomalies")
    except Exception as e:
        logger.error(f"Statistical detection failed: {e}")

    # 4. Rule-based (highest priority — always include, may upgrade severity)
    try:
        rule_results = run_rule_based_detection(entries)
        for idx, score, reason, severity in rule_results:
            if idx in seen_indices:
                # Rule-based always wins severity
                existing = seen_indices[idx]
                existing.score = max(existing.score, score)
                existing.severity = severity
                existing.reason = f"[RULE] {reason} | {existing.reason}"
                existing.method = DetectionMethod.RULE_BASED
                continue
            entry = entries[idx]
            anomaly = Anomaly(
                session_id=session_id,
                log_entry_ids=[entry.id],
                score=score,
                severity=severity,
                reason=f"[RULE] {reason}",
                method=DetectionMethod.RULE_BASED,
                supporting_logs=[entry.raw_line],
            )
            seen_indices[idx] = anomaly
            anomalies.append(anomaly)
        logger.info(f"Rule-based: {len(rule_results)} anomalies")
    except Exception as e:
        logger.error(f"Rule-based detection failed: {e}")

    # 5. Temporal (sliding-window frequency analysis)
    temporal_telemetry: dict = {}
    if enable_temporal:
        try:
            existing_ids = set()
            for a in anomalies:
                existing_ids.update(a.log_entry_ids)
            temporal_anomalies, temporal_telemetry = run_temporal_detection(
                entries, session_id, existing_ids=existing_ids
            )
            for ta in temporal_anomalies:
                anomalies.append(ta)
            logger.info(f"Temporal: {len(temporal_anomalies)} anomalies")
        except Exception as e:
            logger.error(f"Temporal detection failed: {e}")

    duration = time.time() - start_time

    metrics = ModelMetrics(
        session_id=session_id,
        total_logs=len(entries),
        anomalies_detected=len(anomalies),
        contamination_rate=contamination,
        detection_methods=[m.value for m in DetectionMethod],
        tfidf_top_terms=top_terms,
        isolation_forest_params=if_params,
        analysis_duration_seconds=round(duration, 3),
        temporal_telemetry=temporal_telemetry,
    )

    logger.info(f"Detection complete: {len(anomalies)} anomalies in {duration:.2f}s")
    return anomalies, metrics

"""
Temporal Behaviour Intelligence Engine (Phase 3)
=================================================
Detects volumetric and temporal anomalies that single-log ML methods miss.

Techniques implemented:
  1. Sliding-window event frequency analysis (10s, 30s, 1m, 5m)
  2. Per-IP, per-endpoint, per-category grouping
  3. Rolling mean / rolling std / Z-score per window
  4. Exponential Moving Average (EMA) for adaptive baseline
  5. Rate-of-change (derivative) between consecutive windows
  6. HTTP error-rate spikes
  7. Failed-auth burst detection per source IP and distributed credential stuffing
  8. Database connection / resource exhaustion burst detection
  9. Outbound C2 connection burst detection
  10. Unseen protocol probe frequency surges
"""

import re
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional, Any

import numpy as np

from app.models.log_entry import LogEntry, LogLevel
from app.models.anomaly import Anomaly, SeverityLevel, DetectionMethod

logger = logging.getLogger("michael.temporal")

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

WINDOWS_SECONDS = [10, 30, 60, 300]           # sliding windows to evaluate
EMA_ALPHA       = 0.3                          # EMA smoothing factor
Z_THRESHOLD     = 2.5                          # Z-score threshold for spike
ROC_THRESHOLD   = 2.5                          # rate-of-change multiplier
AUTH_BURST      = 5                            # failed-auth count per window to flag
DB_BURST        = 5                            # DB connection failures per window
HTTP_ERR_RATE   = 0.50                         # HTTP error ratio to trigger
OUTBOUND_THRESH = 3                            # suspicious outbound per window

# Regex helpers
_IP_RE   = re.compile(r'\b(?:(\d{1,3}\.){3}\d{1,3})\b')
_HTTP_RE = re.compile(
    r'(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', re.IGNORECASE
)
_HTTP_STATUS_RE = re.compile(r'\b([45]\d{2})\b')   # 4xx / 5xx
_AUTH_FAIL_RE   = re.compile(
    r'(failed\s+password|authentication\s+failure|invalid\s+user|'
    r'login\s+failed|bad\s+password|access\s+denied)', re.IGNORECASE
)
_DB_FAIL_RE = re.compile(
    r'(database\s+connection|connection\s+pool|too\s+many\s+connections|'
    r'deadlock|query\s+timeout|db\s+error)', re.IGNORECASE
)
_OUTBOUND_RE = re.compile(
    r'(outbound|egress|established.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})',
    re.IGNORECASE
)
_RESOURCE_RE = re.compile(
    r'(out\s+of\s+memory|oom|disk\s+full|cpu\s+spike|high\s+load|'
    r'process\s+limit|file\s+descriptor)', re.IGNORECASE
)
_UNSEEN_RE = re.compile(
    r'(unrecognised\s+protocol|unknown\s+protocol|zxqk|probe|unseen)',
    re.IGNORECASE
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _extract_ip(text: str) -> Optional[str]:
    m = _IP_RE.search(text)
    return m.group(0) if m else None


def _extract_endpoint(text: str) -> Optional[str]:
    m = _HTTP_RE.search(text)
    return m.group(1)[:64] if m else None


def _has_http_error(text: str) -> bool:
    return bool(_HTTP_STATUS_RE.search(text))


def _categorise(entry: LogEntry) -> str:
    text = (entry.message or "") + " " + entry.raw_line
    if _AUTH_FAIL_RE.search(text):
        return "auth_failure"
    if _DB_FAIL_RE.search(text):
        return "db_failure"
    if _OUTBOUND_RE.search(text):
        return "outbound"
    if _RESOURCE_RE.search(text):
        return "resource"
    if _UNSEEN_RE.search(text):
        return "unseen"
    if entry.level in (LogLevel.ERROR, LogLevel.CRITICAL):
        return "error"
    return "normal"


def _ts_seconds(entry: LogEntry) -> Optional[float]:
    if entry.timestamp:
        try:
            ts = entry.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.timestamp()
        except Exception:
            return None
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Window Frequency Analysis
# ──────────────────────────────────────────────────────────────────────────────

class _WindowCounter:
    """
    Buckets events into fixed-width time windows and computes
    rolling mean, std, EMA, Z-score and rate-of-change across all buckets.
    """

    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self._buckets: Dict[int, int] = defaultdict(int)
        self._bucket_entry_ids: Dict[int, List[str]] = defaultdict(list)

    def add(self, ts_sec: float, entry_id: Optional[str] = None):
        bucket = int(ts_sec // self.window)
        self._buckets[bucket] += 1
        if entry_id:
            self._bucket_entry_ids[bucket].append(entry_id)

    def compute_stats(self) -> Dict[str, Any]:
        if not self._buckets:
            return {}

        sorted_bucket_keys = sorted(self._buckets.keys())
        counts = [self._buckets[b] for b in sorted_bucket_keys]
        arr = np.array(counts, dtype=float)

        mean = float(np.mean(arr))
        std = float(np.std(arr))

        ema = counts[0]
        spikes = []
        max_z = 0.0
        max_roc = 0.0

        for idx, b in enumerate(sorted_bucket_keys):
            cnt = self._buckets[b]
            if idx > 0:
                ema = EMA_ALPHA * cnt + (1 - EMA_ALPHA) * ema
                prev = counts[idx - 1] if counts[idx - 1] > 0 else 1.0
                roc = (cnt - counts[idx - 1]) / prev
            else:
                roc = 0.0

            z = (cnt - mean) / (std + 1e-9) if std > 0 else 0.0
            if abs(z) > abs(max_z):
                max_z = z
            if roc > max_roc:
                max_roc = roc

            if (z >= Z_THRESHOLD or roc >= ROC_THRESHOLD) and cnt >= 3:
                spikes.append({
                    "bucket": b,
                    "count": cnt,
                    "z_score": round(float(z), 3),
                    "roc": round(float(roc), 3),
                    "entry_ids": list(self._bucket_entry_ids[b]),
                })

        latest = counts[-1]

        return {
            "window_seconds": self.window,
            "n_buckets": len(self._buckets),
            "counts": counts,
            "mean": round(mean, 3),
            "std": round(std, 3),
            "ema": round(ema, 3),
            "z_score": round(max_z, 3),
            "rate_of_change": round(max_roc, 3),
            "latest_count": latest,
            "spike_detected": len(spikes) > 0,
            "spikes": spikes,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Main Temporal Engine
# ──────────────────────────────────────────────────────────────────────────────

class TemporalEngine:
    """
    Analyses event frequency over configurable sliding windows grouped by
    source IP, HTTP endpoint, and event category.
    """

    def __init__(self, windows: List[int] = None):
        self.windows = windows or WINDOWS_SECONDS
        self._ip_counters: Dict[str, Dict[int, _WindowCounter]] = defaultdict(
            lambda: {w: _WindowCounter(w) for w in self.windows}
        )
        self._ep_counters: Dict[str, Dict[int, _WindowCounter]] = defaultdict(
            lambda: {w: _WindowCounter(w) for w in self.windows}
        )
        self._cat_counters: Dict[str, Dict[int, _WindowCounter]] = defaultdict(
            lambda: {w: _WindowCounter(w) for w in self.windows}
        )
        self._global_counters: Dict[int, _WindowCounter] = {
            w: _WindowCounter(w) for w in self.windows
        }
        self._ip_auth_ev: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._ip_outbound_ev: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._ip_db_ev: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._cat_events: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._http_total: Dict[int, int] = defaultdict(int)
        self._http_errors: Dict[int, int] = defaultdict(int)
        self._http_bucket_entry_ids: Dict[int, List[str]] = defaultdict(list)

    def ingest(self, entries: List[LogEntry]):
        """Ingest all log entries and populate counters."""
        for entry in entries:
            ts = _ts_seconds(entry)
            if ts is None:
                continue
            text = (entry.message or "") + " " + entry.raw_line
            ip   = _extract_ip(text)
            ep   = _extract_endpoint(text)
            cat  = _categorise(entry)

            for w in self.windows:
                self._global_counters[w].add(ts, entry.id)

            if ip:
                for w in self.windows:
                    self._ip_counters[ip][w].add(ts, entry.id)
                if _AUTH_FAIL_RE.search(text):
                    self._ip_auth_ev[ip].append((ts, entry.id))
                if _OUTBOUND_RE.search(text):
                    self._ip_outbound_ev[ip].append((ts, entry.id))
                if _DB_FAIL_RE.search(text):
                    self._ip_db_ev[ip].append((ts, entry.id))

            if ep:
                for w in self.windows:
                    self._ep_counters[ep][w].add(ts, entry.id)

            for w in self.windows:
                self._cat_counters[cat][w].add(ts, entry.id)
            self._cat_events[cat].append((ts, entry.id))

            if _HTTP_RE.search(text):
                bucket = int(ts // 60)
                self._http_total[bucket] += 1
                if _has_http_error(text):
                    self._http_errors[bucket] += 1
                    self._http_bucket_entry_ids[bucket].append(entry.id)

    def detect(
        self,
        entries: List[LogEntry],
        session_id: str,
        existing_ids: Optional[set] = None,
    ) -> Tuple[List[Anomaly], Dict[str, Any]]:
        """
        Run temporal anomaly detection and return (anomalies, telemetry).
        """
        existing_ids = existing_ids or set()
        anomalies: List[Anomaly] = []
        telemetry: Dict[str, Any] = {
            "global_windows": {},
            "ip_spikes": [],
            "endpoint_spikes": [],
            "category_spikes": [],
            "auth_burst_ips": [],
            "http_error_rate_buckets": [],
        }

        # 1. Global traffic spikes (System-level indicator; does not flag individual entries as malicious)
        for w in self.windows:
            stats = self._global_counters[w].compute_stats()
            telemetry["global_windows"][f"{w}s"] = stats
            for sp in stats.get("spikes", []):
                score = min(0.95, 0.55 + 0.08 * abs(sp["z_score"]))
                anomalies.append(Anomaly(
                    session_id=session_id,
                    log_entry_ids=[],  # System-wide metric; avoids flagging benign traffic
                    score=round(score, 3),
                    severity=_severity(score),
                    reason=(
                        f"[TEMPORAL] Global traffic spike in {w}s window: "
                        f"{sp['count']} events (Z={sp['z_score']:.2f}, RoC={sp['roc']:.2f}x)"
                    ),
                    method=DetectionMethod.TEMPORAL,
                    metadata={"window": w, "spike": sp},
                ))

        # 2. Per-IP request flood / scraper spikes
        for ip, wmap in self._ip_counters.items():
            for w in self.windows:
                ctr = wmap[w]
                stats = ctr.compute_stats()
                spikes = stats.get("spikes", [])
                # Require >= 5 events in window to avoid false alarms on normal 2-3 req browsing
                valid_spikes = [s for s in spikes if s["count"] >= 5]
                if valid_spikes:
                    sp = valid_spikes[0]
                    score = min(0.95, 0.50 + 0.07 * abs(sp["z_score"]))
                    telemetry["ip_spikes"].append({"ip": ip, "window": w, **sp})
                    all_ip_entry_ids = [eid for s in valid_spikes for eid in s["entry_ids"]]
                    anomalies.append(Anomaly(
                        session_id=session_id,
                        log_entry_ids=all_ip_entry_ids,
                        score=round(score, 3),
                        severity=_severity(score),
                        reason=(
                            f"[TEMPORAL] Frequency spike from IP {ip} in {w}s window: "
                            f"{sp['count']} events (Z={sp['z_score']:.2f})"
                        ),
                        method=DetectionMethod.TEMPORAL,
                        metadata={"ip": ip, "window": w, "spike": sp, "category": "http_flood"},
                    ))
                    break

        # 3. Per-endpoint spikes (e.g. targeted endpoint surge)
        for ep, wmap in self._ep_counters.items():
            for w in self.windows:
                ctr = wmap[w]
                stats = ctr.compute_stats()
                spikes = stats.get("spikes", [])
                if spikes and spikes[0]["count"] >= 10:
                    sp = spikes[0]
                    score = min(0.90, 0.45 + 0.07 * abs(sp["z_score"]))
                    telemetry["endpoint_spikes"].append({"endpoint": ep, "window": w, **sp})
                    all_ep_entry_ids = [eid for s in spikes for eid in s["entry_ids"]]
                    anomalies.append(Anomaly(
                        session_id=session_id,
                        log_entry_ids=all_ep_entry_ids,
                        score=round(score, 3),
                        severity=_severity(score),
                        reason=(
                            f"[TEMPORAL] Request surge on endpoint {ep!r} in {w}s window: "
                            f"{sp['count']} requests (Z={sp['z_score']:.2f})"
                        ),
                        method=DetectionMethod.TEMPORAL,
                        metadata={"endpoint": ep, "window": w, "spike": sp},
                    ))
                    break

        # 4. Auth burst detection per IP
        for ip, ev_list in self._ip_auth_ev.items():
            bursts = _count_bursts(ev_list, window=30, threshold=AUTH_BURST)
            if bursts:
                all_burst_ids = [eid for b in bursts for eid in b["entry_ids"]]
                score = min(0.95, 0.75 + 0.04 * len(bursts))
                telemetry["auth_burst_ips"].append({"ip": ip, "burst_windows": len(bursts)})
                anomalies.append(Anomaly(
                    session_id=session_id,
                    log_entry_ids=all_burst_ids,
                    score=round(score, 3),
                    severity=SeverityLevel.CRITICAL,
                    reason=(
                        f"[TEMPORAL] SSH/Auth brute-force burst from {ip}: "
                        f"{len(bursts)} burst window(s) with >={AUTH_BURST} failures/30s"
                    ),
                    method=DetectionMethod.TEMPORAL,
                    metadata={"ip": ip, "burst_count": len(bursts), "category": "ssh_bruteforce"},
                ))

        # 5. Distributed authentication anomaly burst (across rotating IPs)
        auth_cat_bursts = _count_bursts(self._cat_events["auth_failure"], window=60, threshold=5)
        if auth_cat_bursts:
            all_burst_ids = [eid for b in auth_cat_bursts for eid in b["entry_ids"]]
            score = min(0.95, 0.75 + 0.03 * len(auth_cat_bursts))
            anomalies.append(Anomaly(
                session_id=session_id,
                log_entry_ids=all_burst_ids,
                score=round(score, 3),
                severity=SeverityLevel.HIGH,
                reason=(
                    f"[TEMPORAL] Distributed authentication anomaly surge: "
                    f"{sum(b['count'] for b in auth_cat_bursts)} failed logins clustered in 60s"
                ),
                method=DetectionMethod.TEMPORAL,
                metadata={"category": "auth_anomaly"},
            ))

        # 6. Database connection burst detection
        for ip, ev_list in self._ip_db_ev.items():
            bursts = _count_bursts(ev_list, window=60, threshold=DB_BURST)
            if bursts:
                all_burst_ids = [eid for b in bursts for eid in b["entry_ids"]]
                score = min(0.95, 0.70 + 0.03 * len(bursts))
                anomalies.append(Anomaly(
                    session_id=session_id,
                    log_entry_ids=all_burst_ids,
                    score=round(score, 3),
                    severity=SeverityLevel.HIGH,
                    reason=(
                        f"[TEMPORAL] Database connection exhaustion burst from {ip}: "
                        f"{sum(b['count'] for b in bursts)} connection errors in 60s"
                    ),
                    method=DetectionMethod.TEMPORAL,
                    metadata={"ip": ip, "category": "db_failure"},
                ))

        db_cat_bursts = _count_bursts(self._cat_events["db_failure"], window=60, threshold=DB_BURST)
        if db_cat_bursts:
            all_burst_ids = [eid for b in db_cat_bursts for eid in b["entry_ids"]]
            score = min(0.95, 0.75 + 0.03 * len(db_cat_bursts))
            anomalies.append(Anomaly(
                session_id=session_id,
                log_entry_ids=all_burst_ids,
                score=round(score, 3),
                severity=SeverityLevel.HIGH,
                reason=(
                    f"[TEMPORAL] Database connection pool exhaustion: "
                    f"{sum(b['count'] for b in db_cat_bursts)} failures clustered in 60s"
                ),
                method=DetectionMethod.TEMPORAL,
                metadata={"category": "db_failure"},
            ))

        # 7. Outbound C2 connection burst detection
        for ip, ev_list in self._ip_outbound_ev.items():
            bursts = _count_bursts(ev_list, window=60, threshold=OUTBOUND_THRESH)
            if bursts:
                all_burst_ids = [eid for b in bursts for eid in b["entry_ids"]]
                score = min(0.95, 0.80 + 0.03 * len(bursts))
                anomalies.append(Anomaly(
                    session_id=session_id,
                    log_entry_ids=all_burst_ids,
                    score=round(score, 3),
                    severity=SeverityLevel.CRITICAL,
                    reason=(
                        f"[TEMPORAL] Suspicious outbound C2 connection burst from {ip}: "
                        f"{sum(b['count'] for b in bursts)} outbound sessions in 60s"
                    ),
                    method=DetectionMethod.TEMPORAL,
                    metadata={"ip": ip, "category": "c2_connection"},
                ))

        outbound_cat_bursts = _count_bursts(self._cat_events["outbound"], window=60, threshold=OUTBOUND_THRESH)
        if outbound_cat_bursts:
            all_burst_ids = [eid for b in outbound_cat_bursts for eid in b["entry_ids"]]
            score = min(0.95, 0.82 + 0.03 * len(outbound_cat_bursts))
            anomalies.append(Anomaly(
                session_id=session_id,
                log_entry_ids=all_burst_ids,
                score=round(score, 3),
                severity=SeverityLevel.CRITICAL,
                reason=(
                    f"[TEMPORAL] Outbound network egress burst: "
                    f"{sum(b['count'] for b in outbound_cat_bursts)} suspicious egress sessions in 60s"
                ),
                method=DetectionMethod.TEMPORAL,
                metadata={"category": "c2_connection"},
            ))

        # 8. HTTP error-rate spikes per minute
        for bucket, total in self._http_total.items():
            errors = self._http_errors.get(bucket, 0)
            if total >= 5 and errors / total >= HTTP_ERR_RATE:
                rate = round(errors / total, 3)
                score = min(0.90, 0.55 + 0.3 * rate)
                entry_ids = self._http_bucket_entry_ids.get(bucket, [])
                telemetry["http_error_rate_buckets"].append(
                    {"bucket_minute": bucket, "error_rate": rate,
                     "total": total, "errors": errors}
                )
                anomalies.append(Anomaly(
                    session_id=session_id,
                    log_entry_ids=entry_ids,
                    score=round(score, 3),
                    severity=_severity(score),
                    reason=(
                        f"[TEMPORAL] HTTP error-rate spike: "
                        f"{errors}/{total} requests returned 4xx/5xx "
                        f"({rate*100:.0f}%) in a 1-minute window"
                    ),
                    method=DetectionMethod.TEMPORAL,
                    metadata={"error_rate": rate, "total_requests": total, "category": "http_error_surge"},
                ))

        # 9. Resource exhaustion burst
        res_bursts = _count_bursts(self._cat_events["resource"], window=60, threshold=5)
        if res_bursts:
            all_burst_ids = [eid for b in res_bursts for eid in b["entry_ids"]]
            score = min(0.95, 0.75 + 0.03 * len(res_bursts))
            anomalies.append(Anomaly(
                session_id=session_id,
                log_entry_ids=all_burst_ids,
                score=round(score, 3),
                severity=SeverityLevel.HIGH,
                reason=(
                    f"[TEMPORAL] Resource exhaustion cluster: "
                    f"{sum(b['count'] for b in res_bursts)} memory/process alerts in 60s"
                ),
                method=DetectionMethod.TEMPORAL,
                metadata={"category": "resource_exhaustion"},
            ))

        # 10. Unseen protocol probe burst
        unseen_bursts = _count_bursts(self._cat_events["unseen"], window=60, threshold=5)
        if unseen_bursts:
            all_burst_ids = [eid for b in unseen_bursts for eid in b["entry_ids"]]
            score = min(0.95, 0.72 + 0.03 * len(unseen_bursts))
            anomalies.append(Anomaly(
                session_id=session_id,
                log_entry_ids=all_burst_ids,
                score=round(score, 3),
                severity=SeverityLevel.HIGH,
                reason=(
                    f"[TEMPORAL] Unrecognised protocol burst: "
                    f"{sum(b['count'] for b in unseen_bursts)} unknown probe handshakes in 60s"
                ),
                method=DetectionMethod.TEMPORAL,
                metadata={"category": "unseen_pattern"},
            ))

        # Deduplicate alerts
        deduped: List[Anomaly] = []
        seen_entry_keys = set()
        for a in anomalies:
            key = (a.reason, tuple(sorted(a.log_entry_ids)))
            if key in seen_entry_keys:
                continue
            seen_entry_keys.add(key)
            deduped.append(a)
        anomalies = deduped

        logger.info(
            f"Temporal engine detected {len(anomalies)} temporal anomalies "
            f"across {len(self._ip_counters)} IPs, "
            f"{len(self._ep_counters)} endpoints, "
            f"{len(self._cat_counters)} categories"
        )
        return anomalies, telemetry


# ──────────────────────────────────────────────────────────────────────────────
# Utility functions
# ──────────────────────────────────────────────────────────────────────────────

def _severity(score: float) -> SeverityLevel:
    if score >= 0.85:
        return SeverityLevel.CRITICAL
    if score >= 0.65:
        return SeverityLevel.HIGH
    if score >= 0.40:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def _count_bursts(
    events: List[Tuple[float, str]],
    window: float,
    threshold: int,
) -> List[Dict[str, Any]]:
    """Return list of burst windows where event count >= threshold, with associated entry IDs."""
    if len(events) < threshold:
        return []
    evs = sorted(events, key=lambda x: x[0])
    bursts = []
    i = 0
    while i < len(evs):
        j = i
        matched_ids = []
        while j < len(evs) and evs[j][0] - evs[i][0] <= window:
            matched_ids.append(evs[j][1])
            j += 1
        if j - i >= threshold:
            bursts.append({
                "start": evs[i][0],
                "end": evs[j - 1][0],
                "count": j - i,
                "entry_ids": matched_ids,
            })
            i = j
        else:
            i += 1
    return bursts


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_temporal_detection(
    entries: List[LogEntry],
    session_id: str,
    existing_ids: Optional[set] = None,
    windows: List[int] = None,
) -> Tuple[List[Anomaly], Dict[str, Any]]:
    """
    Convenience wrapper: ingest entries and run temporal detection.
    Returns (anomalies, telemetry).
    """
    engine = TemporalEngine(windows=windows)
    engine.ingest(entries)
    return engine.detect(entries, session_id, existing_ids=existing_ids)

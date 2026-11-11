"""
Log Parser Service - Parses raw log lines into structured LogEntry objects.

Supports:
  - Apache/Nginx access logs
  - Syslog format
  - Application logs (with levels)
  - Generic timestamped logs
  - CSV logs
"""

import re
import csv
import io
import uuid
from datetime import datetime
from typing import List, Optional, Tuple
import logging

from app.models.log_entry import LogEntry, LogLevel, LogSession

logger = logging.getLogger("michael.parser")

# ──────────────────────────────────────────────────────────────────────────────
# Timestamp patterns (ordered by specificity)
# ──────────────────────────────────────────────────────────────────────────────
TIMESTAMP_PATTERNS = [
    # ISO 8601: 2024-01-15T10:30:45.123Z
    (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', '%Y-%m-%dT%H:%M:%S'),
    # ISO date + time: 2024-01-15 10:30:45,123
    (r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[,\.]\d+)?', '%Y-%m-%d %H:%M:%S'),
    # Syslog: Nov 03 10:30:45
    (r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', '%b %d %H:%M:%S'),
    # Apache: 03/Nov/2024:10:30:45 +0000
    (r'\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}', '%d/%b/%Y:%H:%M:%S'),
]

# ──────────────────────────────────────────────────────────────────────────────
# Log level patterns
# ──────────────────────────────────────────────────────────────────────────────
LEVEL_PATTERNS = [
    (r'\b(CRITICAL|FATAL)\b', LogLevel.CRITICAL),
    (r'\b(ERROR|ERR)\b', LogLevel.ERROR),
    (r'\b(WARN(?:ING)?)\b', LogLevel.WARNING),
    (r'\b(INFO(?:RMATION)?)\b', LogLevel.INFO),
    (r'\b(DEBUG|TRACE)\b', LogLevel.DEBUG),
]

# Source/component extraction
SOURCE_PATTERN = re.compile(
    r'(?:kernel|sshd|nginx|apache|mysql|postgres|python|java|node|systemd|cron)\[\d*\]?',
    re.IGNORECASE
)

# IP address pattern
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def extract_timestamp(line: str) -> Tuple[Optional[datetime], str]:
    """Extract and parse timestamp from log line."""
    for pattern, fmt in TIMESTAMP_PATTERNS:
        match = re.search(pattern, line)
        if match:
            ts_str = match.group(0)
            # Normalise
            ts_clean = re.sub(r'[,](\d+)', r'.\1', ts_str).rstrip('Z')
            for f in [fmt, fmt.replace('.%f', ''), fmt + '.%f', fmt + ',%f']:
                try:
                    return datetime.strptime(ts_clean[:len(f) + 5], f), ts_str
                except (ValueError, Exception):
                    continue
    return None, ""


def extract_level(line: str) -> LogLevel:
    """Extract log severity level from line."""
    upper = line.upper()
    for pattern, level in LEVEL_PATTERNS:
        if re.search(pattern, upper):
            return level
    # HTTP status code heuristics
    if re.search(r'\s[45]\d{2}\s', line):
        return LogLevel.ERROR if re.search(r'\s[45][0-9]{2}\s', line) else LogLevel.WARNING
    return LogLevel.UNKNOWN


def extract_source(line: str) -> Optional[str]:
    """Extract source/component from log line."""
    match = SOURCE_PATTERN.search(line)
    if match:
        return match.group(0)
    # Try bracket notation: [component]
    bracket = re.search(r'\[([A-Za-z][A-Za-z0-9_\-]{1,30})\]', line)
    if bracket:
        return bracket.group(1)
    return None


def extract_message(line: str, timestamp_str: str) -> str:
    """Extract the message part of the log line."""
    msg = line
    if timestamp_str:
        msg = msg.replace(timestamp_str, '', 1)
    # Remove level indicators
    for pattern, _ in LEVEL_PATTERNS:
        msg = re.sub(pattern, '', msg, count=1, flags=re.IGNORECASE)
    return msg.strip(' :-|[]')


def parse_log_line(line: str, line_number: int, session_id: str) -> LogEntry:
    """Parse a single log line into a LogEntry."""
    timestamp, ts_str = extract_timestamp(line)
    level = extract_level(line)
    source = extract_source(line)
    message = extract_message(line, ts_str)

    return LogEntry(
        id=str(uuid.uuid4()),
        session_id=session_id,
        timestamp=timestamp,
        level=level,
        source=source,
        message=message or line.strip(),
        raw_line=line.rstrip('\n\r'),
        line_number=line_number,
    )


def parse_csv_log(content: str, session_id: str) -> List[LogEntry]:
    """Parse CSV-formatted log file."""
    entries = []
    reader = csv.DictReader(io.StringIO(content))
    headers = [h.lower() for h in (reader.fieldnames or [])]

    for i, row in enumerate(reader, 1):
        row_lower = {k.lower(): v for k, v in row.items()}
        # Map common CSV column names
        message = (row_lower.get('message') or row_lower.get('msg') or
                   row_lower.get('event') or ' | '.join(row_lower.values()))
        level_str = row_lower.get('level') or row_lower.get('severity') or 'UNKNOWN'
        ts_str = row_lower.get('timestamp') or row_lower.get('time') or row_lower.get('date') or ''

        timestamp, _ = extract_timestamp(ts_str) if ts_str else (None, '')
        try:
            level = LogLevel(level_str.upper())
        except ValueError:
            level = extract_level(message)

        entries.append(LogEntry(
            id=str(uuid.uuid4()),
            session_id=session_id,
            timestamp=timestamp,
            level=level,
            source=row_lower.get('source') or row_lower.get('host') or row_lower.get('service'),
            message=message,
            raw_line=str(dict(row)),
            line_number=i,
        ))
    return entries


def parse_log_content(
    content: str,
    filename: str,
    session_id: str,
) -> Tuple[List[LogEntry], LogSession]:
    """
    Main entry point: parse file content into structured log entries.
    Handles .log, .txt, and .csv files.
    """
    entries: List[LogEntry] = []

    if filename.lower().endswith('.csv'):
        try:
            entries = parse_csv_log(content, session_id)
        except Exception as e:
            logger.warning(f"CSV parse failed ({e}), falling back to line-by-line")

    if not entries:
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped:  # Skip blank lines
                entries.append(parse_log_line(stripped, i, session_id))

    session = LogSession(
        id=session_id,
        filename=filename,
        total_lines=len(entries),
        file_size=len(content.encode('utf-8')),
        status="ready",
    )

    logger.info(f"Parsed {len(entries)} log entries from '{filename}'")
    return entries, session

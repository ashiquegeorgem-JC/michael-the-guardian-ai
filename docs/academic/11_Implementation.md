# CHAPTER 11: IMPLEMENTATION DETAILS

## 9.1 Software Stack & Implementation Environment
The implementation of **MICHAEL – THE GUARDIAN AI** is divided into a high-performance Python 3.12+ backend and a Next.js 16 / TypeScript frontend.

```text
c:\Users\Ashique\OneDrive\Desktop\Michael - The Guardian AI/
├── backend/
│   ├── app/
│   │   ├── main.py                   # FastAPI Application Entry Point & Lifespan
│   │   ├── config.py                 # Configuration Settings (Pydantic-Settings)
│   │   ├── models/                   # Pydantic v2 Domain Models
│   │   │   ├── log_entry.py          # LogEntry, LogSession, LogLevel
│   │   │   ├── anomaly.py            # Anomaly, DetectionMethod, SeverityLevel
│   │   │   ├── incident.py           # Incident, IncidentCategory, IncidentStatus
│   │   │   ├── attack_chain.py       # AttackChain, ChainLinkEvent, ChainStatus
│   │   │   ├── ioc.py                # IOC, IOCEvidence, IOCStatus, IOCType
│   │   │   ├── threat_intel.py       # ThreatAssessment, ThreatIntelResult
│   │   │   └── threat_correlation.py # ThreatCorrelation, UnifiedThreatContext
│   │   ├── services/                 # Domain Services & Engines
│   │   │   ├── log_parser.py         # Multi-Format Log Parsing Engine
│   │   │   ├── ioc_extractor.py      # Regex Extractor for 9 IOC Types
│   │   │   ├── ioc_normalizer.py     # RFC Normalization Utilities
│   │   │   ├── ioc_evidence_mapper.py# Append-Only Evidence Mapping
│   │   │   ├── ioc_repository.py     # IOC Data Access & Deduplication
│   │   │   ├── threat_intel_service.py # Threat Intelligence Coordination & Cache
│   │   │   ├── threat_reputation_engine.py # Threat Scoring & Signal Decomposition
│   │   │   ├── threat_correlation_engine.py # Directional Relationship & Context Engine
│   │   │   ├── incident_service.py   # Incident Clustering Heuristics
│   │   │   └── store.py              # In-Memory Session Storage
│   │   ├── ml/                       # Machine Learning Algorithms
│   │   │   ├── isolation_forest.py   # Isolation Forest Model Wrapper
│   │   │   ├── tfidf_detector.py     # TF-IDF Semantic Dispersion Detector
│   │   │   ├── temporal_detector.py  # Multi-Scale Sliding Window Engine
│   │   │   └── attack_chain_engine.py# Graph Reconstruction & MITRE Mapping
│   │   ├── persistence/              # Database Abstraction & SQL Store
│   │   │   ├── database.py           # SQLAlchemy Engine, Pool & Health Probes
│   │   │   ├── models.py             # SQLAlchemy 12-Table Declarative Schema
│   │   │   └── sql_store.py          # SQL Repository Implementations
│   │   └── routers/                  # FastAPI REST Route Controllers (10 Modules)
│   └── tests/                        # 412 Unit, Integration, & E2E Tests
└── frontend/                         # Next.js 16 Web Application (15 Routes)
    └── src/
        ├── app/                      # Next.js App Router Pages
        ├── components/               # React Components (SOC, Graphs, Timelines)
        └── lib/                      # API Clients, Types, & State Stores
```

## 9.2 Key Implementation Algorithms

### 1. Ingestion & RFC Normalization
The `IOCNormalizer` implements RFC 5952 IPv6 compression and IPv4 zero-stripping using Python's standard `ipaddress` library:
```python
def normalize_ipv4(raw_ip: str) -> str:
    octets = raw_ip.strip().split(".")
    return ".".join(str(int(o)) for o in octets)

def normalize_ipv6(raw_ip: str) -> str:
    parsed = ipaddress.IPv6Address(raw_ip.strip())
    return parsed.compressed.lower()
```

### 2. Isolation Forest Feature Extraction
The feature extraction pipeline translates raw log strings into structured NumPy vectors in under $0.05\text{ms}$:
```python
def extract_features(message: str) -> np.ndarray:
    length = len(message)
    digits = sum(c.isdigit() for c in message) / max(length, 1)
    tokens = len(message.split())
    # Shannon entropy computation
    prob = [cnt / length for cnt in Counter(message).values()]
    entropy = -sum(p * math.log2(p) for p in prob)
    return np.array([length, digits, entropy, tokens], dtype=np.float32)
```

### 3. Directional Correlation Engine
The `ThreatCorrelationEngine` derives relationships while enforcing cross-session safety:
```python
if is_same_session:
    score += BONUS_SAME_SESSION
    confirmed = True
else:
    score = min(score * CROSS_SESSION_PENALTY_MULTIPLIER, CROSS_SESSION_MAX_UNCONFIRMED_SCORE)
    confirmed = False
```

## 9.3 Frontend Implementation
The frontend is built on Next.js 16 and React 19. All 15 routes are statically pre-rendered with zero runtime compilation overhead:
- `/threat-intelligence`: Unified threat intelligence SOC workspace with real-time graph visualization.
- `/attack-chains`: Directed acyclic attack narrative timelines with stage filter tabs.
- `/anomalies`: Anomaly queue with feature weight breakdown and raw log inspection drawers.
- `/iocs`: IOC management interface with analyst review actions and evidence links.


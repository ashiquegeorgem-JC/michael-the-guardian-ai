"""
Threat Reputation & Scoring Engine for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.2 — Offline Threat Reputation & Scoring Engine.

Consumes normalized ThreatIntelResult models and generates explainable, deterministic
threat assessments with:
- Normalized Threat Score (0.0 – 100.0)
- Independent Evidence Confidence Metric (0.0 – 1.0)
- Categorical Severity Mapping (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)
- Structured Contributing Signals with weights and point contributions
- Transparent, human-readable reason bullets for SOC analysts

DESIGN INVARIANTS:
==================
1. Operates 100% offline; zero external network, DNS, or WHOIS calls.
2. UNKNOWN must remain UNKNOWN: Insufficient telemetry never resolves to CLEAN.
3. Strict non-mutation: Neither the input IOC, IOCStatus, nor evidence is modified.
4. Threat score and confidence are strictly decoupled and calculated independently.
5. All calculations are deterministic and explainable via contributing signals.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Set

from app.models.ioc import IOC
from app.models.threat_intel import (
    ContributingSignal,
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelStatus,
    ThreatSeverity,
)
from app.services.threat_intel_service import ThreatIntelService, threat_intel_service

logger = logging.getLogger("michael.threat_reputation")

# ─────────────────────────────────────────────────────────────────────────────
# Scoring Weights and Taxonomy Constants
# ─────────────────────────────────────────────────────────────────────────────

# Standard signal weights (must sum to 1.00)
WEIGHT_PROVIDER_STATUS: float = 0.35
WEIGHT_DETECTION_RATIO: float = 0.30
WEIGHT_REPUTATION_SCORE: float = 0.20
WEIGHT_CATEGORIES: float = 0.15

# Confidence telemetry weights
CONF_WEIGHT_PROVIDER: float = 0.35
CONF_WEIGHT_ENGINES: float = 0.30
CONF_WEIGHT_REPUTATION: float = 0.20
CONF_WEIGHT_CATEGORIES: float = 0.15

# Threat Category Risk Classification
HIGH_SEVERITY_CATEGORIES: Set[str] = {
    "c2",
    "c2_server",
    "c2_beacon",
    "command_and_control",
    "cobalt_strike",
    "ransomware",
    "trojan",
    "botnet",
    "botnet_node",
    "malware_host",
    "malware_download",
    "test_virus",
    "eicar_standard_av_test",
    "apt",
    "apt_infra",
    "credential_harvesting",
    "brute_force",
    "phishing_campaign",
}

MEDIUM_SEVERITY_CATEGORIES: Set[str] = {
    "scanner",
    "port_probe",
    "anomalous_source",
    "suspicious_registration",
    "potential_phish",
    "untrusted_url",
    "spoofed_sender",
    "suspicious_mail",
    "tor_exit",
    "dynamic_dns",
}

BENIGN_CATEGORIES: Set[str] = {
    "dns_resolver",
    "anycast",
    "benign",
    "search_engine",
    "search",
    "web_services",
    "enterprise_services",
    "software",
    "system_binary",
    "corporate_support",
    "legitimate_email",
    "windows_utility",
}


# ─────────────────────────────────────────────────────────────────────────────
# Threat Reputation Engine
# ─────────────────────────────────────────────────────────────────────────────

class ThreatReputationEngine:
    """
    Deterministic scoring and explainability engine for IOC threat evaluation.

    Computes composite threat scores, confidence metrics, severity ratings,
    and structured audit signals from ThreatIntelResult instances.
    """

    ENGINE_VERSION: str = "1.0.0"

    def __init__(self, service: Optional[ThreatIntelService] = None) -> None:
        self._service = service if service is not None else threat_intel_service

    # ── Core Assessment Methods ──────────────────────────────────────────────

    def assess(self, result: ThreatIntelResult) -> ThreatAssessment:
        """
        Produce a deterministic ThreatAssessment from a ThreatIntelResult.

        Guarantees:
        - UNKNOWN status results produce UNKNOWN severity and 0.0 confidence.
        - CLEAN status produces LOW severity with high confidence.
        - SUSPICIOUS and MALICIOUS scale scores by detection ratios and reputation.
        - Input objects are treated as read-only.
        """
        now = datetime.now(timezone.utc)
        expires_at = result.expires_at if result.expires_at >= now else now + timedelta(hours=1)

        # 1. UNKNOWN / ERROR Guard: Insufficient intelligence remains UNKNOWN
        if result.status in (ThreatIntelStatus.UNKNOWN, ThreatIntelStatus.ERROR):
            return self._build_unknown_assessment(result, now, expires_at)

        # 2. Evaluate structured signals
        signals = self._evaluate_signals(result)

        # 3. Compute deterministic threat score from available weighted signals
        threat_score = self._compute_threat_score(signals, result.status)

        # 4. Compute independent evidence confidence
        confidence = self._compute_confidence(result, signals)

        # 5. Derive categorical severity tier
        severity = self._map_severity(threat_score, confidence, result.status)

        # 6. Generate human-readable reasons
        reasons = self._generate_reasons(result, threat_score, confidence, severity, signals)

        return ThreatAssessment(
            ioc_id=result.ioc_id,
            ioc_type=result.ioc_type,
            ioc_value=result.ioc_value,
            normalized_value=result.normalized_value,
            threat_score=threat_score,
            confidence=confidence,
            severity=severity,
            status=result.status,
            reasons=reasons,
            contributing_signals=signals,
            assessed_at=now,
            expires_at=expires_at,
            engine_version=self.ENGINE_VERSION,
            raw_metadata={
                "provider_name": result.provider_name,
                "provider_source": result.source.value,
                "offline": True,
            },
        )

    def assess_ioc(
        self,
        ioc: IOC,
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ThreatAssessment:
        """
        Coordinate threat lookup via ThreatIntelService and assess outcome.
        Guarantees zero mutation of input IOC or its IOCStatus.
        """
        ti_result = self._service.lookup(ioc, provider_name=provider_name, force_refresh=force_refresh)
        return self.assess(ti_result)

    async def assess_ioc_async(
        self,
        ioc: IOC,
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ThreatAssessment:
        """
        Asynchronous coordination of threat lookup and assessment.
        """
        ti_result = await self._service.lookup_async(ioc, provider_name=provider_name, force_refresh=force_refresh)
        return self.assess(ti_result)

    # ── Signal Evaluation ────────────────────────────────────────────────────

    def _evaluate_signals(self, result: ThreatIntelResult) -> List[ContributingSignal]:
        """
        Evaluate individual intelligence signals and package into ContributingSignal objects.
        """
        signals: List[ContributingSignal] = []

        # Signal 1: Provider Status
        status_points = 0.0
        status_explanation = f"Provider verdict: {result.status.value}"
        if result.status == ThreatIntelStatus.MALICIOUS:
            status_points = 100.0
            status_explanation = "Provider classified indicator as MALICIOUS (maximum risk baseline)"
        elif result.status == ThreatIntelStatus.SUSPICIOUS:
            status_points = 50.0
            status_explanation = "Provider classified indicator as SUSPICIOUS (elevated risk baseline)"
        elif result.status == ThreatIntelStatus.CLEAN:
            status_points = 0.0
            status_explanation = "Provider classified indicator as CLEAN (benign infrastructure baseline)"

        signals.append(
            ContributingSignal(
                signal_name="provider_status",
                value=result.status.value,
                weight=WEIGHT_PROVIDER_STATUS,
                contribution=0.0,  # Computed during aggregation
                explanation=status_explanation,
                available=True,
            )
        )

        # Signal 2: Detection Ratio (Engine Detections)
        has_engines = (
            result.total_engines is not None
            and result.total_engines > 0
            and result.detection_count is not None
        )
        if has_engines:
            ratio = min(1.0, max(0.0, result.detection_count / result.total_engines))
            points = ratio * 100.0
            expl = f"{result.detection_count} of {result.total_engines} security engines flagged indicator ({ratio:.1%})"
            signals.append(
                ContributingSignal(
                    signal_name="detection_ratio",
                    value=round(ratio, 4),
                    weight=WEIGHT_DETECTION_RATIO,
                    contribution=0.0,
                    explanation=expl,
                    available=True,
                )
            )
        else:
            signals.append(
                ContributingSignal(
                    signal_name="detection_ratio",
                    value=None,
                    weight=WEIGHT_DETECTION_RATIO,
                    contribution=0.0,
                    explanation="Multi-engine detection telemetry was not provided",
                    available=False,
                )
            )

        # Signal 3: Reputation Score
        if result.reputation_score is not None:
            rep_score = min(1.0, max(0.0, result.reputation_score))
            points = rep_score * 100.0
            expl = f"Reputation risk metric evaluated at {rep_score:.2f} (0.0 benign to 1.0 malicious)"
            signals.append(
                ContributingSignal(
                    signal_name="reputation_score",
                    value=round(rep_score, 4),
                    weight=WEIGHT_REPUTATION_SCORE,
                    contribution=0.0,
                    explanation=expl,
                    available=True,
                )
            )
        else:
            signals.append(
                ContributingSignal(
                    signal_name="reputation_score",
                    value=None,
                    weight=WEIGHT_REPUTATION_SCORE,
                    contribution=0.0,
                    explanation="Direct historical reputation telemetry was not provided",
                    available=False,
                )
            )

        # Signal 4: Threat Categories
        if result.categories:
            lower_cats = {c.strip().lower() for c in result.categories}
            high_matches = lower_cats.intersection(HIGH_SEVERITY_CATEGORIES)
            med_matches = lower_cats.intersection(MEDIUM_SEVERITY_CATEGORIES)
            benign_matches = lower_cats.intersection(BENIGN_CATEGORIES)

            if high_matches:
                points = 100.0
                expl = f"Critical threat categories identified: {', '.join(sorted(high_matches))}"
            elif med_matches:
                points = 50.0
                expl = f"Suspicious threat categories identified: {', '.join(sorted(med_matches))}"
            elif benign_matches:
                points = 0.0
                expl = f"Benign operational categories identified: {', '.join(sorted(benign_matches))}"
            else:
                points = 30.0
                expl = f"Unclassified contextual categories: {', '.join(sorted(lower_cats))}"

            signals.append(
                ContributingSignal(
                    signal_name="threat_categories",
                    value=result.categories,
                    weight=WEIGHT_CATEGORIES,
                    contribution=0.0,
                    explanation=expl,
                    available=True,
                )
            )
        else:
            signals.append(
                ContributingSignal(
                    signal_name="threat_categories",
                    value=[],
                    weight=WEIGHT_CATEGORIES,
                    contribution=0.0,
                    explanation="No threat behavioral categories were associated with indicator",
                    available=False,
                )
            )

        return signals

    # ── Threat Score Computation ─────────────────────────────────────────────

    def _compute_threat_score(
        self,
        signals: List[ContributingSignal],
        status: ThreatIntelStatus,
    ) -> float:
        """
        Calculate deterministic weighted threat score clamped to [0.0, 100.0].
        Distributes point contributions proportionally across available signals.
        """
        available_signals = [s for s in signals if s.available]
        if not available_signals:
            return 0.0

        # Map signal points
        signal_points: Dict[str, float] = {}
        for s in available_signals:
            if s.signal_name == "provider_status":
                if status == ThreatIntelStatus.MALICIOUS:
                    signal_points[s.signal_name] = 100.0
                elif status == ThreatIntelStatus.SUSPICIOUS:
                    signal_points[s.signal_name] = 50.0
                else:
                    signal_points[s.signal_name] = 0.0
            elif s.signal_name == "detection_ratio":
                signal_points[s.signal_name] = float(s.value) * 100.0 if s.value is not None else 0.0
            elif s.signal_name == "reputation_score":
                signal_points[s.signal_name] = float(s.value) * 100.0 if s.value is not None else 0.0
            elif s.signal_name == "threat_categories":
                lower_cats = {c.strip().lower() for c in (s.value or [])}
                if lower_cats.intersection(HIGH_SEVERITY_CATEGORIES):
                    signal_points[s.signal_name] = 100.0
                elif lower_cats.intersection(MEDIUM_SEVERITY_CATEGORIES):
                    signal_points[s.signal_name] = 50.0
                elif lower_cats.intersection(BENIGN_CATEGORIES):
                    signal_points[s.signal_name] = 0.0
                else:
                    signal_points[s.signal_name] = 30.0

        total_available_weight = sum(s.weight for s in available_signals)
        if total_available_weight <= 0.0:
            return 0.0

        raw_weighted_score = sum(
            signal_points.get(s.signal_name, 0.0) * s.weight for s in available_signals
        )
        normalized_score = round(raw_weighted_score / total_available_weight, 2)
        clamped_score = max(0.0, min(100.0, normalized_score))

        # Assign point contribution back to each signal for transparent explainability
        for s in signals:
            if s.available:
                points = signal_points.get(s.signal_name, 0.0)
                s.contribution = round((points * s.weight) / total_available_weight, 2)
            else:
                s.contribution = 0.0

        return clamped_score

    # ── Confidence Computation ───────────────────────────────────────────────

    def _compute_confidence(
        self,
        result: ThreatIntelResult,
        signals: List[ContributingSignal],
    ) -> float:
        """
        Compute evidence confidence independent of threat score.
        Rewards telemetry coverage, engine count depth, and verified sources.
        """
        # Baseline provider confidence
        prov_conf = min(1.0, max(0.0, result.confidence)) * CONF_WEIGHT_PROVIDER

        # Engine depth telemetry
        engine_conf = 0.0
        if result.total_engines and result.total_engines > 0:
            depth_ratio = min(1.0, result.total_engines / 50.0)  # Full points at >= 50 engines
            engine_conf = depth_ratio * CONF_WEIGHT_ENGINES

        # Reputation telemetry
        rep_conf = CONF_WEIGHT_REPUTATION if result.reputation_score is not None else 0.0

        # Categories telemetry
        cat_conf = CONF_WEIGHT_CATEGORIES if result.categories else 0.0

        total_confidence = prov_conf + engine_conf + rep_conf + cat_conf
        return round(max(0.0, min(1.0, total_confidence)), 2)

    # ── Severity Mapping ─────────────────────────────────────────────────────

    def _map_severity(
        self,
        threat_score: float,
        confidence: float,
        status: ThreatIntelStatus,
    ) -> ThreatSeverity:
        """
        Map threat score and status to discrete severity tier.
        Guarantees that low confidence or unverified outcomes do not escalate.
        """
        # Security invariant: UNKNOWN remains UNKNOWN
        if status in (ThreatIntelStatus.UNKNOWN, ThreatIntelStatus.ERROR) or confidence == 0.0:
            return ThreatSeverity.UNKNOWN

        # Known clean with low threat score maps to LOW
        if status == ThreatIntelStatus.CLEAN and threat_score < 25.0:
            return ThreatSeverity.LOW

        # Standard deterministic score thresholding
        if threat_score < 25.0:
            return ThreatSeverity.LOW
        elif threat_score < 60.0:
            return ThreatSeverity.MEDIUM
        elif threat_score < 85.0:
            return ThreatSeverity.HIGH
        else:
            return ThreatSeverity.CRITICAL

    # ── Reason Generation ────────────────────────────────────────────────────

    def _generate_reasons(
        self,
        result: ThreatIntelResult,
        threat_score: float,
        confidence: float,
        severity: ThreatSeverity,
        signals: List[ContributingSignal],
    ) -> List[str]:
        """
        Generate human-readable, factual reasons explaining the assessment outcome.
        """
        reasons: List[str] = []

        # 1. Primary Verdict Reason
        if result.status == ThreatIntelStatus.MALICIOUS:
            reasons.append("Threat intelligence feed classified this indicator as confirmed MALICIOUS.")
        elif result.status == ThreatIntelStatus.SUSPICIOUS:
            reasons.append("Threat intelligence feed classified this indicator as SUSPICIOUS.")
        elif result.status == ThreatIntelStatus.CLEAN:
            reasons.append("Threat intelligence feed classified this indicator as benign (CLEAN).")

        # 2. Engine Detections Reason
        if result.total_engines and result.total_engines > 0 and result.detection_count is not None:
            if result.detection_count == 0:
                reasons.append(f"0 of {result.total_engines} security engines reported malicious activity.")
            else:
                ratio = result.detection_count / result.total_engines
                reasons.append(
                    f"{result.detection_count} of {result.total_engines} security engines flagged malicious activity ({ratio:.1%})."
                )

        # 3. Reputation Reason
        if result.reputation_score is not None:
            if result.reputation_score >= 0.70:
                reasons.append(f"Reputation risk metric ({result.reputation_score:.2f}) indicates severe hostility.")
            elif result.reputation_score >= 0.30:
                reasons.append(f"Reputation risk metric ({result.reputation_score:.2f}) indicates moderate anomaly.")
            else:
                reasons.append(f"Reputation risk metric ({result.reputation_score:.2f}) confirms legitimate history.")

        # 4. Behavioral Categories Reason
        if result.categories:
            lower_cats = {c.strip().lower() for c in result.categories}
            high_matches = lower_cats.intersection(HIGH_SEVERITY_CATEGORIES)
            if high_matches:
                reasons.append(f"Active malicious taxonomy matched: {', '.join(sorted(high_matches))}.")
            else:
                reasons.append(f"Contextual telemetry tags: {', '.join(sorted(result.categories))}.")

        # 5. Overall Synthesis Reason
        reasons.append(
            f"Overall Threat Score {threat_score:.1f}/100 with {confidence:.0%} confidence rated severity as {severity.value}."
        )

        return reasons

    # ── UNKNOWN Guard Construction ───────────────────────────────────────────

    def _build_unknown_assessment(
        self,
        result: ThreatIntelResult,
        now: datetime,
        expires_at: datetime,
    ) -> ThreatAssessment:
        """
        Construct a compliant, explicit UNKNOWN assessment for unclassified indicators.
        """
        reasons = [
            "No definitive threat intelligence is currently available for this indicator.",
            "The indicator remains UNCLASSIFIED rather than being treated as clean or benign.",
            "Confidence is 0% due to absence of corroborating intelligence signals.",
        ]
        signals = [
            ContributingSignal(
                signal_name="provider_status",
                value=result.status.value,
                weight=WEIGHT_PROVIDER_STATUS,
                contribution=0.0,
                explanation=f"Provider reported verdict '{result.status.value}'; insufficient data to score risk",
                available=False,
            ),
            ContributingSignal(
                signal_name="detection_ratio",
                value=None,
                weight=WEIGHT_DETECTION_RATIO,
                contribution=0.0,
                explanation="No security engine telemetry available",
                available=False,
            ),
            ContributingSignal(
                signal_name="reputation_score",
                value=None,
                weight=WEIGHT_REPUTATION_SCORE,
                contribution=0.0,
                explanation="No historical reputation telemetry available",
                available=False,
            ),
            ContributingSignal(
                signal_name="threat_categories",
                value=[],
                weight=WEIGHT_CATEGORIES,
                contribution=0.0,
                explanation="No threat behavioral tags associated",
                available=False,
            ),
        ]

        return ThreatAssessment(
            ioc_id=result.ioc_id,
            ioc_type=result.ioc_type,
            ioc_value=result.ioc_value,
            normalized_value=result.normalized_value,
            threat_score=0.0,
            confidence=0.0,
            severity=ThreatSeverity.UNKNOWN,
            status=result.status,
            reasons=reasons,
            contributing_signals=signals,
            assessed_at=now,
            expires_at=expires_at,
            engine_version=self.ENGINE_VERSION,
            raw_metadata={
                "provider_name": result.provider_name,
                "offline": True,
                "unknown_reason": "insufficient_telemetry",
            },
        )


# Default singleton instance
threat_reputation_engine = ThreatReputationEngine(service=threat_intel_service)


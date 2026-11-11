# Slide 02: The Cybersecurity Problem

## Modern SOC Bottlenecks & Operational Failures

---

### Key Points
- **Unmanageable Velocity:** Enterprise datacenters produce millions of log entries daily; manual inspection is mathematically impossible.
- **Alert Fatigue:** Brittle static threshold rules emit thousands of false-positive alarms daily, desensitizing analysts.
- **Siloed Context:** Alerts for authentication, network sockets, and web errors are reported independently, leaving analysts to mentally reconstruct attacks.
- **Telemetry Deficit Trap:** Missing records in external threat feeds are often naively assumed to be "Clean," missing zero-day C2 infrastructure.

---

### Suggested Visual
- Diagram showing an overwhelmed SOC analyst buried under alarms while a stealthy attacker bypasses perimeter static rules.

---

### Presenter Notes
"The fundamental problem in cybersecurity operations today is not a lack of data—it is an overload of context-free alerts. Human analysts cannot review 50,000 logs a minute, and static threshold rules generate immense alert fatigue while missing low-and-slow attacks."


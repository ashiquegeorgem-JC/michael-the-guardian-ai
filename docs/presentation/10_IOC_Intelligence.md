# Slide 10: IOC Intelligence & RFC Normalization

## Canonical Deduplication & Forensic Provenance

---

### Key Points
- **9 Indicator Classes:** IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, File Path.
- **RFC Normalization:**
  - IPv4: Strips leading zeros (`010.001.020.005` $\to$ `10.1.20.5`).
  - IPv6: RFC 5952 lowercase compressed format (`2001:0DB8::1` $\to$ `2001:db8::1`).
  - Domain & Hash: Case-folding; strips default HTTP/HTTPS ports.
- **Append-Only Evidence Mapping (`IOCEvidence`):**
  - Every indicator links to exact `event_id`, `session_id`, `timestamp`, and source line number.
- **Decoupled States:**
  - Structural `ValidationStatus` (`VALID`, `INVALID`, `SUSPICIOUS`).
  - Analyst `IOCStatus` (`EXTRACTED`, `UNDER_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`).

---

### Suggested Visual
- Table showing raw indicator variants collapsing into a single canonical normalized IOC with linked evidence pointers.

---

### Presenter Notes
"In forensic analysis, details matter. We enforce strict RFC normalization so duplicate representations don't corrupt intelligence lookups, and every indicator links back to the exact source line where it was observed."


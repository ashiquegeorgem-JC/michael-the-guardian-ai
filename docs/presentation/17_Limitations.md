# Slide 17: Operational & Subsystem Limitations

## Scientific Honesty & Boundary Disclosure

---

### Key Points
- **Controlled Benchmark Datasets:**
  - Evaluated on strictly partitioned synthetic datasets; live enterprise deployment requires continuous calibration against site-specific noise.
- **Provider API Quotas:**
  - Public free-tier VirusTotal lookups are bounded by provider rate limits (4 req/min); production scaling requires commercial multi-provider licenses.
- **Low-and-Slow Horizon Bounds:**
  - Sliding windows currently span up to 300 seconds ($5\text{ minutes}$); multi-week drip campaigns evade short-horizon Z-scores.
- **Human-in-the-Loop by Design:**
  - Autonomous destructive blocking is deliberately disabled to avoid denial-of-service from false positives on critical business systems.

---

### Suggested Visual
- Diagram showing the human analyst in the loop reviewing prescriptive playbooks rather than blind automated blocking.

---

### Presenter Notes
"In keeping with academic integrity, we openly acknowledge our operational boundaries. Our benchmarks reflect controlled synthetic validation, our sliding windows are currently bounded to 5 minutes, and we intentionally keep human analysts in the loop for remediation."


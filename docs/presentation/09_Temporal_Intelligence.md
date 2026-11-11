# Slide 09: Temporal Behaviour Intelligence

## Capturing Time-Series Dynamics & Rate of Change

---

### Key Points
- **Point-Based Limitation:** A single password failure or database error is normal; a rapid burst indicates compromise.
- **Multi-Scale Sliding Windows:** Evaluates streams forward-causally across 4 concurrent horizons:
  $$\mathcal{W} = \{10\text{s}, \quad 30\text{s}, \quad 60\text{s}, \quad 300\text{s}\}$$
- **Rolling Statistical Telemetry:**
  - Rolling Mean ($\mu_W$) & Rolling Standard Deviation ($\sigma_W$)
  - Exponential Moving Average ($\text{EMA}_t$)
  - Rolling Z-Score: $Z_W(t) = \frac{x_t - \mu_W(t)}{\sigma_W(t) + \epsilon}$
  - First-order rate of change: $\Delta v(t) = \frac{\Delta x}{\Delta t}$
- **Burst Detections:** Catches brute-force surges, HTTP 5xx error spikes, and periodic C2 beaconing.

---

### Suggested Visual
- Multi-scale time-series graph showing a sudden event rate spike with moving standard deviation envelope and Z-score alert trigger.

---

### Presenter Notes
"Temporal intelligence allows MICHAEL to see the rhythm of an attack. By tracking rolling statistics across 10-second to 5-minute sliding windows, we catch volumetric surges and burst attacks that point-based detectors miss."


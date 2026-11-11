# TEMPORAL BEHAVIOUR INTELLIGENCE

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Motivation: Beyond Point-Based Inspection

Point-based log inspection evaluates each log message in total isolation. While effective for explicit syntax exploits (such as SQL injection strings), point-based inspection is completely blind to attacks whose maliciousness is defined by **frequency, timing, and rate of change**:
- An authentication failure is normal; **50 failures in 10 seconds** is a brute-force attack.
- A database query error is routine; a **300% surge in 30 seconds** indicates a denial-of-service or deadlock.
- An outbound firewall connection is routine; **periodic 60-second connection bursts** indicates command-and-control (C2) beaconing.

To capture these threat vectors, MICHAEL incorporates a **Temporal Behaviour Intelligence Engine** that analyzes continuous time-series dynamics across calibrated multi-scale sliding windows.

---

## 2. Mathematical Modeling of Sliding Windows

The engine processes log entries in chronological order $t_1 \le t_2 \le \dots \le t_n$ and maintains four distinct sliding window scales:

$$\mathcal{W} = \{10\text{s}, 30\text{s}, 60\text{s}, 300\text{s}\}$$

For any point in time $t$ and window duration $W \in \mathcal{W}$, the active window interval is:
$$I_W(t) = [t - W, t]$$

Let $N_W(t)$ be the set of log events occurring within $I_W(t)$. The engine computes four rolling statistical indicators:

### 2.1 Rolling Mean ($\mu_W$)
Represents the baseline event velocity across window horizon $W$:
$$\mu_W(t) = \frac{1}{|N_W(t)|} \sum_{i \in N_W(t)} x_i$$
Where $x_i$ represents the event weight or count per unit sub-interval.

### 2.2 Rolling Standard Deviation ($\sigma_W$)
Quantifies the instantaneous volumetric volatility:
$$\sigma_W(t) = \sqrt{\frac{1}{|N_W(t)| - 1} \sum_{i \in N_W(t)} \left(x_i - \mu_W(t)\right)^2}$$

### 2.3 Exponential Moving Average ($\text{EMA}_W$)
Assigns exponentially decreasing weights to older events within the window, delivering high sensitivity to sudden spikes:
$$\text{EMA}_t = \alpha \cdot x_t + (1 - \alpha) \cdot \text{EMA}_{t-1}$$
Where the smoothing factor $\alpha$ is calibrated to the window scale:
$$\alpha = \frac{2}{k + 1}, \quad k \approx \text{number of expected intervals in } W$$

### 2.4 Rolling Z-Score ($Z_W$)
Measures the number of standard deviations the current instantaneous rate $x_t$ deviates from the rolling baseline:
$$Z_W(t) = \frac{x_t - \mu_W(t)}{\sigma_W(t) + \epsilon}$$
Where $\epsilon = 10^{-6}$ prevents division by zero during quiescent intervals.

---

## 3. Rate-of-Change & Burst Detection

In addition to absolute deviations, the engine computes the first-order discrete derivative (rate of change):
$$\Delta v(t) = \frac{x_t - x_{t - \delta t}}{\delta t}$$

When $\Delta v(t)$ exceeds calibrated thresholds, the engine flags a **burst anomaly** across specific event categories:
1. **Authentication Burst (Brute Force):**
   $$\text{Rate}(\text{AuthFailed}) > 5 \text{ events} / 10\text{s} \implies \text{CRITICAL Anomaly}$$
2. **HTTP 5xx Error Surge (DoS / Service Degradation):**
   $$Z_{30\text{s}}(\text{HTTP 5xx}) \ge 3.0 \implies \text{HIGH Anomaly}$$
3. **Outbound Connection Burst (C2 / Port Scan):**
   $$Z_{60\text{s}}(\text{Outbound SYN}) \ge 2.5 \implies \text{HIGH Anomaly}$$
4. **Database Error Spikes (Pool Exhaustion / Deadlock):**
   $$\text{Rate}(\text{DB Error}) > 10 \text{ events} / 30\text{s} \implies \text{HIGH Anomaly}$$

---

## 4. Multi-Scale Horizon Justification

| Horizon ($W$) | Primary Threat Vector Detected | Operational Rationale |
|---|---|---|
| **$10\text{s}$ (Micro-window)** | Automated dictionary brute-force, high-rate SYN flood, rapid API abuse. | Captures violent short-duration bursts before server buffers crash. |
| **$30\text{s}$ (Short window)** | Web application fuzzing, vulnerability scanners (Nikto, SQLmap). | Distinguishes human browsing patterns from automated scanning loops. |
| **$60\text{s}$ (Medium window)** | Periodic C2 beaconing pulses, credential cycling. | Provides sufficient sample density to evaluate rolling standard deviation. |
| **$300\text{s}$ (Macro-window)** | Distributed slow-rate port sweeps, resource exhaustion (memory leak, thread starvation). | Establishes the authoritative operational baseline for macro trend comparison. |

---

## 5. Anti-Leakage & Causal Integrity Constraints

To ensure rigorous mathematical integrity:
- **Strictly Causal (Forward-Pass Only):** Event windows are constructed strictly backwards in time ($[t - W, t]$). No future lookahead ($[t, t + W]$) is permitted.
- **Timezone Awareness:** Timestamps are normalized into explicit UTC objects before interval sorting.
- **Clock Drift Tolerance:** Events arriving out of order are re-indexed into a chronological priority queue before window statistics are calculated.


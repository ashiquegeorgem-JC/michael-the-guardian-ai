# CHAPTER 9: MATHEMATICAL & ENGINEERING METHODOLOGY

## 7.1 Data Ingestion & Lexical Preprocessing
Log entries are ingested as raw strings and tokenized into structured `LogEntry` records:
$$\text{LogEntry} = \langle id, session\_id, t_{\text{UTC}}, level, source, m, \text{raw\_line}, \ell \rangle$$
Where $t_{\text{UTC}}$ is a timezone-aware UTC datetime object, $m$ is the cleaned message string, and $\ell \in \mathbb{N}$ is the exact physical line number in the source file.

## 7.2 Anomaly Detection Methodology

### 7.2.1 Isolation Forest Spatial Partitioning
For each message $m$, the feature extractor constructs a numeric vector:
$$\mathbf{x} = [\text{len}(m), \quad \text{digits\_ratio}(m), \quad H(m), \quad \text{token\_count}(m)]$$
Where Shannon character entropy $H(m)$ is:
$$H(m) = -\sum_{i=1}^V p(c_i) \log_2 p(c_i)$$

The anomaly score $s(x, n)$ over an ensemble of $t$ isolation trees is:
$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$
Where $\mathbb{E}(h(x))$ is the average path length across all trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree built over $n$ samples:
$$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$$

### 7.2.2 TF-IDF Semantic Dispersion Modeling
The corpus vocabulary is weighted using term frequency-inverse document frequency:
$$\text{TF-IDF}(t, d, D) = \left(\frac{f_{t, d}}{\sum_{t'} f_{t', d}}\right) \times \left(\ln\frac{1 + |D|}{1 + |\{d \in D : t \in d\}|} + 1\right)$$
The semantic dispersion score is computed from the L2-norm of rare exploit tokens:
$$\text{Score}_{\text{TF-IDF}}(d) = \min\left(1.0, \frac{\|\mathbf{v}_d\|_2 - \mu_{\text{TF-IDF}}}{2.5 \cdot \sigma_{\text{TF-IDF}}}\right)$$

### 7.2.3 Ensemble Score Fusion
Individual model outputs are fused via weighted maximum combination:
$$\text{Score}_{\text{final}} = \max\left(\text{Score}_{\text{rules}}, \quad 0.50 \cdot s_{\text{IF}} + 0.35 \cdot \text{Score}_{\text{TF-IDF}} + 0.15 \cdot Z_{\text{stat}}\right)$$

## 7.3 Multi-Scale Temporal Sliding Window Mathematics
For sliding window horizons $W \in \{10\text{s}, 30\text{s}, 60\text{s}, 300\text{s}\}$, the rolling mean $\mu_W(t)$, rolling standard deviation $\sigma_W(t)$, and rolling Z-score $Z_W(t)$ are computed forward-causally:
$$Z_W(t) = \frac{x_t - \mu_W(t)}{\sigma_W(t) + 10^{-6}}$$
Discrete rate of change is monitored:
$$\Delta v(t) = \frac{x_t - x_{t - \delta t}}{\delta t}$$
Surges exceeding $Z_W \ge 2.5$ or $\Delta v > \theta_{\text{burst}}$ trigger temporal anomaly detections.

## 7.4 Threat Reputation Scoring & Independent Confidence
Raw threat intelligence telemetry is evaluated by the Threat Reputation Engine:
$$\text{ThreatScore} = \text{clamp}\left(\text{BaseScore}(\text{status}) + \sum_{i} w_i \cdot s_i, \quad 0.0, \quad 100.0\right)$$
$$\text{Confidence} = \text{clamp}\left(C_{\text{base}} \times \left(\frac{\text{EnginesTotal}}{\text{MaxEngineThreshold}}\right) + C_{\text{vendor\_reputation}}, \quad 0.0, \quad 1.0\right)$$
Missing external provider records ($404$) map strictly to:
$$\text{ThreatScore} = 0.0, \quad \text{Confidence} = 0.0, \quad \text{Severity} = \text{UNKNOWN}$$

## 7.5 Directional Threat Correlation Mathematics
Correlation confidence $C_{\text{corr}} \in [0.0, 1.0]$ is derived from explicit references ($0.95$), shared events ($0.60$), and temporal proximity:
$$C_{\text{temp}}(\Delta t) = \begin{cases} 
0.40 & \text{if } \Delta t \le 30\text{s} \text{ (Immediate)} \\
0.30 & \text{if } 30\text{s} < \Delta t \le 300\text{s} \text{ (Short)} \\
0.20 & \text{if } 300\text{s} < \Delta t \le 900\text{s} \text{ (Extended)} \\
0.00 & \text{if } \Delta t > 900\text{s} \text{ (Out-of-Window; Rejected)}
\end{cases}$$
Cross-session correlations enforce:
$$C_{\text{cross}} = \min(C_{\text{raw}} \times 0.40, \quad 0.35), \quad \text{confirmed} = \text{False}$$
All directional links are consolidated into the `UnifiedThreatContext`.


# MACHINE LEARNING METHODOLOGY

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Overview & Theoretical Framework

Intrusion detection in enterprise server logs presents severe data modeling hurdles:
1. **Extreme Class Imbalance:** Legitimate operational events constitute $>99.9\%$ of typical log volume.
2. **Absence of Ground Truth:** In live operational environments, logs are unlabelled, rendering supervised classifiers impractical for zero-day threats.
3. **High Cardinality & Structural Diversity:** Log messages mix static template strings with dynamic variables (IP addresses, GUIDs, timestamps, file paths).

To overcome these constraints without generating excessive false-positive alarms, MICHAEL adopts a **Hybrid Multi-Model Ensemble** combining unsupervised spatial partitioning, natural language semantic dispersion, statistical boundary estimation, deterministic heuristic rules, and multi-scale temporal frequency modeling.

```text
Log Entry Text ──┬──▶ Feature Extraction (Length, Digits, Entropy) ──▶ Isolation Forest ──┐
                 ├──▶ Tokenization & N-Gram Extraction ──────────────▶ TF-IDF Model     ──┼──▶ Hybrid Score Fusion ──▶ Anomaly Object
                 ├──▶ Statistical Quantitative Bounds ───────────────▶ Z-Score Model    ──┤
                 └──▶ Known Attack Signatures ───────────────────────▶ Heuristic Rules  ──┘
```

---

## 2. Model 1: Isolation Forest (Unsupervised Tree Partitioning)

### 2.1 Theoretical Basis
Traditional anomaly detection algorithms construct a profile of normal instances and classify points outside that profile as anomalous. **Isolation Forest** (Liu, Ting, and Zhou) isolates anomalies directly by exploiting two quantitative properties of anomalous data points:
- They are a minority mechanism consisting of few instances.
- They possess attribute values that are structurally distinct from normal instances.

Because anomalies are "few and different," they are isolated closer to the root of a random decision tree than normal instances.

### 2.2 Feature Representation
For each `LogEntry`, the feature extractor derives a numeric feature vector $\mathbf{x} = [f_1, f_2, f_3, f_4]$:
1. **Message Length ($f_1$):** Total character count $\text{len}(m)$. Buffer overflow attempts, SQL injection payloads, and Java stack traces exhibit abnormally high lengths.
2. **Numeric Density ($f_2$):** Proportion of numeric characters $\frac{\sum \mathbb{I}(c \in [0-9])}{\text{len}(m)}$. Automated port sweeps, memory address dumps, and hex shellcode display elevated numeric ratios.
3. **Character Entropy ($f_3$):** Shannon entropy of character frequency distribution:
   $$H(m) = -\sum_{i=1}^{V} p(c_i) \log_2 p(c_i)$$
   Base64-encoded payloads, encrypted C2 beacons, and randomized script variables exhibit significantly higher entropy than natural language log statements.
4. **Token Count ($f_4$):** Word count resulting from whitespace splitting.

### 2.3 Partitioning Algorithm & Anomaly Score
An Isolation Tree ($iTree$) is constructed by recursively partitioning a dataset $X$ until either:
1. The tree reaches a maximum height limit $h_{max} = \lceil \log_2(n) \rceil$.
2. The node contains only a single instance $|X| \le 1$.
3. All data points in the node have identical values.

The anomaly score $s(x, n)$ for an instance $x$ over an ensemble of $t$ isolation trees is defined as:
$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$

Where:
- $h(x)$ is the path length (number of edges traversed from root to terminating leaf) for instance $x$.
- $\mathbb{E}(h(x))$ is the expected path length averaged across all $t$ trees in the forest:
  $$\mathbb{E}(h(x)) = \frac{1}{t} \sum_{i=1}^t h_i(x)$$
- $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree (BST) built over $n$ samples, acting as the normalisation factor:
  $$c(n) = 2 \ln(n - 1) + 0.5772156649 \text{ (Euler-Mascheroni constant)} - \frac{2(n - 1)}{n}$$

### 2.4 Score Interpretation
- If $\mathbb{E}(h(x)) \to 0 \implies s \to 1$: Instance is isolated in very few splits and is classified as **strongly anomalous**.
- If $\mathbb{E}(h(x)) \to c(n) \implies s \to 0.5$: Instance exhibits median path length and lacks distinct anomaly signals.
- If $\mathbb{E}(h(x)) \to n - 1 \implies s \to 0$: Instance requires deep tree traversal to isolate and is classified as **normal**.

In MICHAEL, the raw score is normalized into $[0.0, 1.0]$ with an isolation threshold calibrated via contamination parameter $\gamma = 0.05$.

---

## 3. Model 2: TF-IDF Semantic Dispersion

### 3.1 Motivation
Structural feature vectors (length, entropy) can overlook semantic attacks where a log entry has normal length but contains highly anomalous tokens (e.g., `UNION SELECT`, `/etc/shadow`, `chmod 777`).

### 3.2 Feature Extraction
The text of the log message is tokenized using alphanumeric boundary splitting with punctuation retention for shell metacharacters. The **Term Frequency-Inverse Document Frequency (TF-IDF)** weight for term $t$ in log message $d$ within log corpus $D$ is computed as:
$$\text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \text{IDF}(t, D)$$

Where:
$$\text{TF}(t, d) = \frac{f_{t, d}}{\sum_{t' \in d} f_{t', d}}$$
$$\text{IDF}(t, D) = \ln\left(\frac{1 + |D|}{1 + |\{d \in D : t \in d\}|}\right) + 1$$

### 3.3 Semantic Anomaly Calculation
Log messages containing terms that appear frequently in routine operations (e.g., `GET`, `HTTP/1.1`, `sshd`, `connection`) receive low IDF weights. Conversely, rare exploit vocabulary receives high IDF weights. 

The semantic anomaly score for a log entry $d$ is derived from the normalized L2-norm of its TF-IDF vector:
$$\text{Score}_{\text{TF-IDF}}(d) = \min\left(1.0, \frac{\|\mathbf{v}_d\|_2 - \mu_{\text{TF-IDF}}}{k \cdot \sigma_{\text{TF-IDF}}}\right)$$
Entries exceeding $2.5$ standard deviations above the corpus mean are flagged as semantic outliers.

---

## 4. Model 3: Statistical Z-Score Outlier Detection

### 4.1 Quantitative Boundary Modeling
For quantitative numerical distributions (such as per-minute request frequencies, response times, or failed attempt counters), MICHAEL applies parametric statistical boundary detection.

Assuming a distribution with empirical mean $\mu$ and standard deviation $\sigma$:
$$Z = \frac{x - \mu}{\sigma}$$

Where:
$$\mu = \frac{1}{N}\sum_{i=1}^N x_i, \quad \sigma = \sqrt{\frac{1}{N}\sum_{i=1}^N (x_i - \mu)^2}$$

### 4.2 Non-Parametric IQR Fallback
To protect against skewed, non-Gaussian distributions, the engine supports Interquartile Range (IQR) gating:
$$\text{IQR} = Q_3 - Q_1$$
$$\text{Outlier Threshold} = Q_3 + 1.5 \times \text{IQR}$$
Values exceeding the threshold receive scaled statistical anomaly scores.

---

## 5. Model 4: Deterministic Heuristic Rules

### 5.1 Role of Rules in a Machine Learning Pipeline
Pure unsupervised machine learning cannot guarantee $100\%$ precision on known, unambiguous attack signatures. To avoid false negatives on verified critical vulnerabilities, MICHAEL integrates a deterministic heuristic rule engine executing compiled regular expressions for verified patterns:
- **SQL Injection:** Matches patterns such as `UNION\s+SELECT`, `OR\s+1=1`, `INFORMATION_SCHEMA`, `'--`.
- **Path Traversal:** Matches `(?:\.\./|\.\.\\){2,}`, `%2e%2e%2f`, `/etc/passwd`.
- **Brute Force Burst:** Matches repeated occurrences of `Failed password for invalid user` or `authentication failure`.
- **Command Injection:** Matches pipe-chained bash operators such as `;\s*cat\s+/etc`, `\|\s*nc\s+-e`, `/dev/tcp/`.

When a deterministic rule fires, it provides an immediate baseline score ($0.85–0.95$) with explicit `rule_name` and explanatory diagnostic text.

---

## 6. Ensemble Fusion & Scoring Architecture

The final anomaly assessment for any individual log entry synthesizes outputs across all active detectors:

$$\text{FinalScore} = \max\left(\text{Score}_{\text{Rules}}, \quad w_1 \cdot \text{Score}_{\text{IF}} + w_2 \cdot \text{Score}_{\text{TF-IDF}} + w_3 \cdot \text{Score}_{\text{Stat}}\right)$$

Where default weights are parameterized as:
- $w_1 = 0.50$ (Isolation Forest)
- $w_2 = 0.35$ (TF-IDF Semantic)
- $w_3 = 0.15$ (Statistical Quantitative)

### Severity Tier Classification
$$\text{Severity} = \begin{cases} 
\text{CRITICAL} & \text{if } \text{FinalScore} \ge 0.85 \\
\text{HIGH} & \text{if } 0.70 \le \text{FinalScore} < 0.85 \\
\text{MEDIUM} & \text{if } 0.40 \le \text{FinalScore} < 0.70 \\
\text{LOW} & \text{if } \text{FinalScore} < 0.40 
\end{cases}$$

---

## 7. Model Limitations

1. **Unsupervised Contamination Assumptions:** Isolation Forest relies on a contamination parameter $\gamma$. If a training batch is already heavily contaminated with unflagged attacks ($>20\%$), the tree partition depth for attacks increases, slightly degrading sensitivity.
2. **Short Message Cold-Start:** Very short log messages (e.g., `systemd: Started Cron`) possess minimal character entropy and few n-grams, making purely statistical classification less informative without temporal context.
3. **Synthetic Validation Boundary:** Benchmarks conducted in this project reflect strictly partitioned, held-out synthetic scenarios designed to prevent spatial/temporal leakage. Live enterprise deployment requires continuous retuning against site-specific baseline traffic.


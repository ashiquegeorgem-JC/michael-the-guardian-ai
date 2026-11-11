# CHAPTER 4: LITERATURE CONTEXT & RELATED WORK

## 2.1 Evolution of Log Parsing & Extraction
Early approaches to log analysis relied on manual regular expressions tailored to specific log schemas. Vaarandi (2003) pioneered automated log clustering with Simple Logfile Clustering Tool (SLCT). Later, He et al. (2017) conducted a comprehensive evaluation of automated log parsers (including Drain, Spell, and AEL), demonstrating that fixed-depth tree parsing (Drain) achieves high accuracy on structured templates. 

However, automated log parsers often discard non-template tokens—precisely where security analysts find critical adversarial indicators, such as obfuscated command-line parameters or shell injection code. In MICHAEL, lexical extraction is coupled with raw line preservation, ensuring forensic completeness.

## 2.2 Machine Learning for Anomaly Detection
Unsupervised anomaly detection in high-dimensional telemetry has been extensively investigated. Liu, Ting, and Zhou (2008, 2012) introduced **Isolation Forest**, proving that random recursive partitioning isolates sparse outliers significantly faster than distance- or density-based estimators ($O(t \cdot \psi \log \psi)$ complexity). Isolation Forest has demonstrated superior resistance to the "curse of dimensionality" when processing numeric feature vectors.

In natural language log processing, Salton and Buckley (1988) established the foundational mathematics of Term Frequency-Inverse Document Frequency (TF-IDF). While modern deep neural approaches such as DeepLog (Du et al., 2017) and LogRobust (Zhang et al., 2019) utilize recurrent neural networks or Transformer embeddings, they require extensive GPU compute resources and suffer from high inference latency. MICHAEL demonstrates that combining unsupervised Isolation Forest with TF-IDF semantic dispersion and deterministic heuristic rules delivers sub-millisecond evaluation latency suitable for real-time edge monitoring.

## 2.3 Temporal Dynamics & Time-Series Anomaly Detection
Point-based anomaly detection models fail to capture volumetric burst attacks. Chandola, Banerjee, and Kumar (2009) established the formal taxonomy of point, contextual, and collective anomalies. In time-series monitoring, moving-window statistics and Exponential Moving Averages (EMA) have long been utilized in network traffic anomaly detection (Lakhina et al., 2004). 

MICHAEL builds upon this foundation by implementing multi-scale sliding windows ($10\text{s}$, $30\text{s}$, $60\text{s}$, $300\text{s}$) that evaluate both rolling Z-scores and first-order rates of change, bridging point anomaly detection with temporal burst intelligence.

## 2.4 Threat Intelligence & Correlation Taxonomies
The integration of Indicators of Compromise (IOCs) into automated detection pipelines is standardized by OASIS Cyber Threat Intelligence standards, including STIX (Structured Threat Information Expression) and TAXII (Barnum, 2012). External intelligence services, such as VirusTotal, provide multi-engine consensus data.

However, existing literature rarely addresses the **telemetry deficit problem**: how systems should respond when an external feed returns a 404 Not Found response. In most commercial systems, absence of intelligence is naively conflated with a "Clean" verdict. Furthermore, automated correlation systems frequently suffer from state pollution, where correlation automatically overwrites ticket severity. MICHAEL's architecture directly addresses these gaps by enforcing strict mathematical separation of Threat Score from Confidence and decoupling correlation from classification.


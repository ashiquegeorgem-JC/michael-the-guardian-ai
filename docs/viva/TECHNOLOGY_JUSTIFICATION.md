# MICHAEL – THE GUARDIAN AI
## Technology Justification Sheet

**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Version:** Phase 5.3 — Final Defense Preparation  
**Purpose:** Viva-ready justifications for every technology decision in the project

---

> Each entry answers: What is it? Why was it chosen? What alternatives exist? What are the trade-offs?

---

## BACKEND TECHNOLOGIES

---

### Python 3.12

**What it is:** General-purpose programming language. The de facto standard for data science and ML applications.

**Why chosen:**
- Native ecosystem for ML (scikit-learn, NumPy, pandas).
- FastAPI, the chosen web framework, is Python-native.
- Extensive community libraries for log parsing, cryptography, and data processing.
- Strong async/await support via asyncio for concurrent request handling.

**Alternatives considered:** Java (verbose, heavyweight for ML integration), Go (excellent performance but immature ML ecosystem), Node.js (JS-first, ML ecosystem is secondary).

**Trade-offs:** Python has a Global Interpreter Lock (GIL) that limits true CPU parallelism for multi-threaded workloads. For CPU-bound ML inference at very high throughput, a compiled language would outperform Python. At the scale of an academic prototype processing hundreds to thousands of events, Python performance is acceptable.

---

### FastAPI 0.115+

**What it is:** Modern Python web framework for building APIs with automatic OpenAPI documentation generation.

**Why chosen:**
- Native async/await support for high-concurrency request handling.
- Automatic request validation via Pydantic models — data integrity enforced at the API boundary.
- Automatic OpenAPI/Swagger documentation at `/docs` — reduces documentation burden.
- Native WebSocket support for real-time event streaming to the SOC dashboard.
- Dependency injection system makes testing clean — repositories and services are injected, not hardcoded.

**Alternatives considered:** Flask (synchronous by default, manual validation), Django REST Framework (heavier, ORM-centric, less suited for lightweight ML service), Tornado (async but less ergonomic).

**Trade-offs:** FastAPI is relatively new compared to Flask/Django. Community depth is smaller. For this project, its technical strengths outweigh the ecosystem maturity trade-off.

---

### Pydantic v2

**What it is:** Data validation library that uses Python type hints to define and validate data schemas.

**Why chosen:**
- Enforces strict data contracts at every API boundary. Invalid log entries are rejected with structured error messages.
- Used to define all request/response models — the API schema is derived from Python code, ensuring the code and documentation stay in sync.
- Pydantic v2 (Rust-compiled validators) is significantly faster than Pydantic v1.

**Trade-offs:** Pydantic v2 introduced breaking changes from v1. Migration required adjustments to existing code. The performance improvement justifies the migration cost.

---

### SQLAlchemy 2.0+

**What it is:** Python ORM (Object-Relational Mapper) for database interaction.

**Why chosen:**
- Abstracts SQL dialect differences between SQLite and PostgreSQL — the same Python code runs against both.
- Declarative model definitions create clean, readable data models.
- Connection pooling, transaction management, and migration support are built-in.
- Core + ORM layers allow dropping to raw SQL when needed for performance-critical queries.

**Alternatives considered:** Raw SQL (portable but verbose and error-prone), Tortoise ORM (async-native but less mature), Peewee (lighter but fewer features).

**Trade-offs:** SQLAlchemy adds an abstraction layer. Complex queries sometimes produce suboptimal SQL that raw SQL would express more efficiently. For this project's query complexity, this trade-off is acceptable.

---

### Scikit-learn 1.5+

**What it is:** Standard Python ML library providing implementations of classic ML algorithms.

**Why chosen:**
- Provides `IsolationForest` — the core anomaly detection algorithm.
- Provides `TfidfVectorizer` — the text feature extraction component.
- Well-documented, well-tested, and widely accepted in academic and industry contexts.
- Consistent API (`fit`, `transform`, `predict`) reduces learning curve.

**Alternatives considered:** PyTorch/TensorFlow (deep learning, massively overengineered for this problem), custom implementation (unnecessary reinvention).

**Trade-offs:** Scikit-learn is not designed for online/streaming learning. The Isolation Forest model is trained offline and does not update incrementally as new data arrives. This is a documented limitation.

---

### Isolation Forest (Algorithm)

**What it is:** Unsupervised anomaly detection algorithm based on the concept of isolating anomalies via random recursive partitioning.

**Why chosen:**
- Does not require labelled training data — suitable for the unlabelled log analysis problem.
- Scales well to high-dimensional feature spaces.
- Computationally efficient — O(n log n) training complexity.
- Naturally handles the class imbalance problem (attacks are rare relative to normal events).
- Strong theoretical foundation and widespread adoption in anomaly detection literature.

**Alternatives considered:**
- One-Class SVM (sensitive to hyperparameter tuning, computationally expensive for high-dimensional data).
- Local Outlier Factor (LOF) (computationally expensive at inference time — O(n) per new point).
- Autoencoder (neural network reconstruction error — requires labelled data to tune threshold, more complex to train).

**Trade-offs:** Isolation Forest cannot distinguish between types of anomalies — it only identifies that something is unusual. The downstream pipeline (IOC extraction, threat intelligence) provides the classification layer.

---

### TF-IDF (Algorithm)

**What it is:** Term Frequency–Inverse Document Frequency — a numerical text representation technique.

**Why chosen:**
- Converts raw log message text into numerical features that the ML model can process.
- Naturally emphasises rare, specific terms (which are more likely to indicate anomalies) over common terms.
- Lightweight and fast — no GPU required, no pre-training needed.
- Established method for log analysis in academic literature.

**Alternatives considered:**
- Word2Vec/FastText (requires large training corpus, adds complexity).
- BERT embeddings (high quality but computationally expensive; overkill for log token analysis).
- Simple bag-of-words (lacks IDF weighting, treats all terms equally).

**Trade-offs:** TF-IDF is a bag-of-words method. It does not capture word order or semantic similarity. "authentication failed" and "failed authentication" are treated identically, which is acceptable for log analysis but not for general NLP tasks.

---

### NumPy 1.26+

**What it is:** Fundamental array computation library for Python.

**Why chosen:** Required by scikit-learn. Used directly for feature vector construction, numerical operations, and array manipulation throughout the ML pipeline.

**Trade-offs:** None significant. NumPy is the standard numerical computing foundation for Python ML; there is no meaningful alternative.

---

### ReportLab 4.2+

**What it is:** Python library for programmatic PDF generation.

**Why chosen:** Used to generate PDF security reports from the backend. Allows the system to export structured threat intelligence reports, IOC summaries, and incident reports as professional PDF documents.

**Alternatives considered:** WeasyPrint (HTML-to-PDF, requires browser-compatible HTML), fpdf2 (simpler API but less powerful layout control), Pandoc (external process dependency).

**Trade-offs:** ReportLab's API is lower-level than template-based alternatives. More verbose code is required for complex layouts. The output quality and control is excellent.

---

## FRONTEND TECHNOLOGIES

---

### Next.js 15 / React 19

**What it is:** Next.js is a React framework providing server-side rendering, static generation, file-system routing, and production build optimisation.

**Why chosen:**
- File-system routing simplifies the management of 15 application routes without manual router configuration.
- Built-in TypeScript support.
- Production build optimisation (code splitting, image optimisation, bundle minimisation) is automatic.
- Large ecosystem and community.
- API routes can proxy backend calls, avoiding CORS issues in production.

**Alternatives considered:** Vite + React (SPA only, no SSR), Angular (more opinionated, heavier), Vue.js (smaller ecosystem for enterprise tooling).

**Trade-offs:** Next.js adds build complexity relative to a plain React SPA. The features it provides (routing, SSR, build optimisation) justify this complexity for a 15-route production application.

---

### TypeScript 5.7+

**What it is:** Statically typed superset of JavaScript.

**Why chosen:**
- Catches type errors at compile time rather than runtime — critical for a security dashboard where data structure integrity matters.
- Improves IDE support (autocomplete, refactoring).
- API response types shared between frontend and backend documentation are explicitly defined and checked.
- Reduces a class of bugs common in untyped JavaScript (undefined property access, incorrect API response handling).

**Alternatives considered:** Plain JavaScript (no type safety), Flow (smaller ecosystem).

**Trade-offs:** TypeScript adds a compilation step and requires explicit type annotations. The safety benefits outweigh this overhead for a production application.

---

### Tailwind CSS 3.4+

**What it is:** Utility-first CSS framework providing composable style classes.

**Why chosen:**
- Rapid UI development without writing custom CSS files.
- Consistent design system through configured colour palette, spacing, and typography scales.
- Production builds eliminate unused CSS via tree-shaking, resulting in minimal CSS bundle size.

**Alternatives considered:** CSS Modules (more verbose, less rapid prototyping), Bootstrap (component-based but less flexible for custom dashboard layouts), styled-components (CSS-in-JS, adds runtime overhead).

**Trade-offs:** Tailwind class names can make HTML verbose. For a dashboard with many similar components, this is managed through component abstraction in React.

---

## DATABASE TECHNOLOGIES

---

### SQLite (Development/Testing)

**What it is:** Embedded relational database stored in a single file. No separate server required.

**Why chosen for development:**
- Zero configuration — no database server to install or configure.
- Runs entirely in-process — test suite can spin up and tear down databases instantly.
- Full SQL support via SQLAlchemy abstraction.

**Trade-offs:** SQLite does not support concurrent write access well. It is not suitable for production multi-user workloads. Used only for development and testing.

---

### PostgreSQL / Supabase (Production Target)

**What it is:** PostgreSQL is a full-featured open-source relational database. Supabase is a managed PostgreSQL platform with additional services (REST API, authentication, real-time subscriptions).

**Why chosen for production:**
- Full concurrent read/write support — suitable for multi-user production workloads.
- Strong ACID compliance and transaction isolation.
- Advanced query capabilities (window functions, full-text search, JSONB fields) available if needed.
- Supabase provides managed hosting, automatic backups, and a REST API layer without managing a PostgreSQL server directly.
- Row-level security (available via Supabase) enables future multi-tenancy.

**Alternatives considered:** MySQL (less advanced feature set), MongoDB (document store — does not enforce relational integrity), Redis (cache-only, not durable enough for primary data storage).

**Trade-offs:** Requires a Supabase account or self-hosted PostgreSQL for production. The development path (SQLite) allows the project to run without any external service dependency.

---

## COMMUNICATION TECHNOLOGIES

---

### REST API (HTTP/JSON)

**What it is:** Representational State Transfer — standard HTTP-based API architecture using JSON data exchange.

**Why chosen:**
- Universal interoperability — any HTTP client can consume the API.
- Stateless by design — scales horizontally without server affinity.
- FastAPI generates OpenAPI documentation automatically, making the API self-documenting.
- Well-understood by all reviewers and examiners.

**Trade-offs:** REST is synchronous request/response. Real-time event delivery requires polling or WebSockets (addressed separately). REST is not ideal for streaming large volumes of events — WebSocket handles this.

---

### WebSockets

**What it is:** Bidirectional persistent TCP connection over HTTP that enables the server to push events to the client.

**Why chosen:**
- Enables the SOC dashboard to receive real-time anomaly alerts without polling.
- Server-push model is more efficient than polling for event-driven data.
- FastAPI provides native WebSocket support with minimal configuration.

**Trade-offs:** WebSocket connections are persistent — they consume server resources. For large numbers of concurrent SOC analysts, connection management becomes important. The current implementation uses a simple connection list; a production system would use a message queue for event distribution.

---

## DEVELOPMENT & BUILD TOOLS

---

### Git

**What it is:** Distributed version control system.

**Why chosen:** Industry standard. Enables change tracking, branching, collaboration, and GitHub release packaging.

---

### Python `unittest` Framework

**What it is:** Python's built-in test framework.

**Why chosen:**
- No external dependency required — built into Python.
- 412 tests cover all backend subsystems.
- Compatible with standard CI/CD runners.

**Alternatives considered:** pytest (feature-rich, more idiomatic for modern Python projects). `unittest` was used throughout the project for consistency.

---

### npm / Node.js Build System

**What it is:** JavaScript package manager and build toolchain powering the Next.js frontend.

**Why chosen:** Required by Next.js. The build system handles TypeScript compilation, CSS processing, code splitting, and bundle optimisation automatically.

---

*End of Technology Justification Sheet*

---

**MICHAEL – THE GUARDIAN AI**  
*"Intelligence That Watches. AI That Protects."*  
Phase 5.3 — Final Defense Preparation


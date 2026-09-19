# CYVORA — Cyber Vulnerability & Operational Response Architecture
**Autonomous Threat Detection, Anomaly Triage, Contextual Risk Scoring & Deterministic Prevention**

*BUILDATHON 2026 Entry*

> **Scope Note**: Defensive actions (`BLOCK`/`RATE_LIMIT`) are enforced safely at the application/API level, not via real network infrastructure. System-activity and authentication-log monitoring are architecturally supported but out of scope for this MVP; network events and security alerts are fully implemented.

---

## Engineering Philosophy

> **"CYVORA deliberately prioritizes deterministic, auditable and operationally reliable security decisions over unnecessary AI complexity."**

In modern Security Operations Centers (SOCs), operational failure rarely stems from an inability to generate speculative predictions. It stems from alert fatigue, non-deterministic outputs, unpredictable execution latency, unverified mitigations, and fragile data pipelines.

CYVORA intentionally avoids hype-driven architectural anti-patterns and focuses strictly on engineering fundamentals:
- **Determinism**: Every policy decision (`ALLOW`, `ALERT`, `RATE_LIMIT`, `BLOCK`) follows reproducible, mathematical rules and explicit confidence boundaries rather than generative sampling.
- **Low Operational Overhead**: Fast tabular inference on CPU without heavy GPU clustering or slow inference runtimes.
- **Explainability**: Clear feature threshold contributions and risk-scoring factors rather than computationally prohibitive black-box explainers during streaming flow ingestion.
- **Persistence**: Every event, prediction, response decision, and audit record is atomically committed to PostgreSQL within a single relational transaction.
- **Verification**: Defensive actions are actively verified post-execution, recording cryptographic and state evidence before logging.
- **Controlled Automation**: Predictable enforcement graduated by threat severity, source context history, and anomaly indicators.
- **Reliable SOC Workflow**: Resilient HTTP polling with $O(1)$ client-side deduplication rather than connection-churn-prone streaming sockets.

---

### Architectural Choices: What We Deliberately Chose vs. What We Cut

| # | Deliberate Architectural Choice | Alternative Deliberately Excluded | Rationale |
|---|---|---|---|
| **1** | **Deterministic Response Engine** | LLM Investigation Chatbot | Non-generative response policy executes with low-overhead deterministic evaluation and zero risk of hallucinated CVEs or prompt injection. |
| **2** | **Temporal Context & Risk Scoring** | Attack-Graph Reconstruction | Sliding 10-minute temporal window assesses burst frequency, historical threat recurrence, and source behavior without unbounded graph traversal overhead. |
| **3** | **Frozen Supervised Ensemble + Isolation Forest** | Runtime Online / Continuous Learning | Supervised tree ensemble handles known attack classes while an Isolation Forest detects novelty. Prevents live data poisoning and catastrophic forgetting. |
| **4** | **PostgreSQL Relational Audit Persistence** | Cosmetic Report Generators | Structured, indexed 5-table relational schema with atomic transaction rollback provides an auditable paper trail for SIEM and forensic querying. |
| **5** | **Deterministic Feature & Rule Explanations** | SHAP / Shapley Attribution | Real-time flow triage requires immediate feature thresholds; calculating Shapley values on 80+ features per flow introduces severe CPU bottlenecks. |
| **6** | **Tree-Based Tabular ML Ensembles** | LSTM / Transformer Deep Learning | Tabular network flow records (durations, byte counts, flag ratios) are optimal for tree ensembles (Random Forest + Extra Trees), achieving fast inference on standard CPU hardware. |
| **7** | **HTTP Polling + $O(1)$ Deduplication** | WebSocket Stateful Streaming | Stateless, resilient polling eliminates connection dropouts, proxy incompatibilities, and socket pool exhaustion during high-volume bursts. |
| **8** | **Unified SOC Command Dashboard** | Fragmented Multi-Page Rabbit Holes | Single-pane-of-glass architecture brings live telemetry, threat analytics, context risk breakdown, and prevention verification into an actionable workflow. |

---

## The Problem

Modern enterprise networks face tens of thousands of network flows per second. Traditional defenses and contemporary AI tools suffer from critical structural weaknesses:

1. **Alert Fatigue & Noise**: Classifiers without contextual awareness flag isolated anomalies as emergencies, overwhelming analysts.
2. **Slow, Unreliable Automation**: SOAR playbooks that depend on generative models or complex microservice meshes introduce seconds of latency, allowing fast-moving attacks to progress.
3. **Unverified Responses**: Most systems trigger a firewall command or API call and assume success without actively verifying that the source is actually blocked.
4. **Data Ephemerality**: Security events frequently live only in UI memory or temporary logs, making post-incident forensic reconstruction difficult.

---

## The Solution

CYVORA is a modular, high-efficiency cybersecurity detection and response engine. It combines:
- A hierarchical **tree-based ensemble** (Global Random Forest + Extra Trees + Web Specialist) for known attack traffic classification.
- An **Isolation Forest anomaly detector** that flags novel traffic deviating from learned benign baselines.
- A **deterministic contextual risk engine** that inspects past source behavior within a sliding temporal window to dampen false positives and escalate repeat offenders.
- An **automated response policy** that triggers application-level enforcement (`ALLOW`, `ALERT`, `RATE_LIMIT`, `BLOCK`).
- An **independent response verifier** that inspects active enforcement tables to confirm defensive state before logging.
- An **atomic PostgreSQL persistence layer** that commits the full event-to-mitigation lifecycle in a single transaction.
- An **enterprise SOC dashboard** providing analysts with unified visibility into threats, risk scores, and system operational health.

---

## Pipeline Architecture

```
  Incoming Security Event (Network Flow Features)
                     │
                     ▼
          [ Known Threat ML Engine ]
      (V21.1 Global Ensemble + Specialist)
                     │
                     ▼
        [ Anomaly / Novelty Detector ]
    (Isolation Forest: Unsupervised Baseline)
                     │
                     ▼
        [ Contextual Risk Engine ]
  (10-Minute Sliding Window & Source History)
                     │
                     ▼
      [ False-Positive Reduction Filter ]
   (Normal Concurrence & Statistical Checks)
                     │
                     ▼
         [ Response Policy Engine ]
    (Deterministic Matrix: ALLOW/ALERT/RL/BLOCK)
                     │
                     ▼
     [ Application-Level Enforcement ]
    (In-Memory TTL Protection & Rate Tables)
                     │
                     ▼
       [ Response Verification Layer ]
  (Active State Validation & Evidence Collection)
                     │
                     ▼
      [ PostgreSQL Transaction Commit ]
   (SecurityEvent → Prediction → Action → Audit)
                     │
                     ▼
       [ Unified Analyst SOC Dashboard ]
   (HTTP Polling with O(1) ID Deduplication)
```

---

## AI & Machine Learning Architecture

### 1. Known Threat Classification (Supervised Tree Ensemble)
- **Model Structure**: Hierarchical ensemble combining a Global Random Forest, a Global Extra Trees classifier, and an optimized Web Attack Specialist.
- **Feature Space**: 83 flow-based network features derived from standard flow telemetry (packet sizes, flow duration, inter-arrival times, TCP flag counts, window sizes).
- **Design Objective**: Fast tabular inference with balanced class coverage across DoS, PortScan, Patator brute force, Web Attacks, and Infiltration without deep neural network dependencies.

### 2. Anomaly & Novelty Detection (Unsupervised Isolation Forest)
- **Model**: Scikit-Learn `IsolationForest` calibrated on benign baseline network traffic.
- **Function**: Rather than claiming speculative zero-day classification, it performs **anomaly and novelty detection that identifies behavior deviating from learned benign patterns**.
- **Novelty Triage Matrix**:
  - `KNOWN_BENIGN`: Supervised model predicts Benign with high confidence; anomaly detector confirms normal flow.
  - `KNOWN_THREAT`: Supervised model identifies known signature with high confidence.
  - `UNKNOWN_ANOMALOUS`: Supervised model confidence is low or predicts benign, but anomaly score exceeds threshold ($\ge 0.60$). Automatically escalates to `ALERT` for analyst monitoring without disruptive blind blocking.

---

## Contextual Risk & False-Positive Reduction

Isolated packet metrics are insufficient to determine malicious intent. CYVORA's context risk engine evaluates:
1. **Source Temporal Window**: Queries the last 10 minutes of activity for the given source identifier (bounded to 50 recent events to prevent unbounded database scans).
2. **Frequency & Burst Factor**: Analyzes rapid request spikes from the same source.
3. **Escalation History**: Evaluates whether the source has past high-severity detections.
4. **False-Positive Suppression**:
   - `NORMAL_TRAFFIC_CONCURRENCE`: When both the classifier and anomaly detector indicate normal traffic, risk is heavily dampened.
   - `ISOLATED_ANOMALY`: A single outlier flow from an otherwise clean source is flagged for review rather than immediate blocking, preventing service disruption.

---

## Response Engine & Application-Level Enforcement

CYVORA enforces a **deterministic, non-generative response policy**:

| Policy Action | Trigger Conditions | Application-Level Enforcement Mechanism |
|---|---|---|
| `ALLOW` | Benign classification, low anomaly, low contextual risk | Traffic permitted through standard evaluation. |
| `ALERT` | Medium severity threats, or `UNKNOWN_ANOMALOUS` novelty triage | Audit record generated; analyst flag dispatched; source monitored. |
| `RATE_LIMIT` | Moderate risk scores, suspicious frequency bursts | Source IP placed in temporary rate-limiting table (120-second TTL). |
| `BLOCK` | Critical/High severity attacks (DDoS, Botnet, Exploits) or high risk | Source IP placed in blocked blacklist table (300-second TTL); subsequent requests immediately rejected with `HTTP 403 Forbidden`. |

*Note: In the current prototype, enforcement operates at the application/API level. Production network-layer integration is detailed in the roadmap.*

---

## Response Verification

CYVORA does not assume enforcement succeeded simply because an action function was called.
- The **Response Verifier** queries the active prevention tables post-execution.
- Confirms whether the source ID is actively registered in the expected state with valid remaining TTL.
- Generates a structured verification evidence payload (`VERIFIED`, `FAILED`, or `NOT_APPLICABLE`).
- Persists the verification evidence into the `response_actions` record and appends a `RESPONSE_VERIFIED` audit log entry.

---

## Authentication & Security

- **JWT Access Control**: All sensitive and state-changing endpoints (`/predict`, `/events/recent`, `/stats`, `/database/status`) require standard Bearer tokens signed via HS256.
- **Bcrypt Password Hashing**: User passwords are encrypted with bcrypt ($12$ rounds) before database insertion; plain text passwords are never stored or logged.
- **Strict Environment Isolation**: Secrets (`JWT_SECRET`, `DATABASE_URL`) are read strictly from environment variables or `.env` files and validated on server startup.
- **Fail-Safe Integrity**: Database connection drops fail gracefully without crashing the core prediction pipeline, while alerting the operator.

---

## PostgreSQL Persistence Layer

Persistence is structured around a normalized 5-table relational schema designed for atomic consistency:

```
  ┌──────────────┐
  │    users     │
  └──────┬───────┘
         │
  ┌──────▼───────┐        ┌──────────────────┐
  │security_event├───────►│    audit_logs    │
  └──────┬───────┘        └──────────────────┘
         │
  ┌──────▼───────┐
  │ predictions  │
  └──────┬───────┘
         │
  ┌──────▼───────┐
  │response_action│
  └──────────────┘
```

1. **`users`**: Analyst identities, bcrypt password hashes, roles, and registration timestamps.
2. **`security_events`**: Immutable raw ingress flows, timestamps, source IDs, and raw feature JSONB.
3. **`predictions`**: ML classification output, confidence, anomaly scores, novelty labels, risk scores, and context summaries.
4. **`response_actions`**: Policy decision (`ALLOW`/`ALERT`/`RATE_LIMIT`/`BLOCK`), reason, verification status, and verification evidence.
5. **`audit_logs`**: Append-only security audit events (`PREDICTION_MADE`, `RESPONSE_BLOCK`, `RESPONSE_VERIFIED`).

*All four operational tables are written and committed within a **single atomic transaction** per `/predict` invocation. If any insert fails, the session rolls back completely.*

---

## Technology Stack

### Backend
- **Language**: Python 3.10
- **Framework**: FastAPI (ASGI) with Pydantic v2 validation
- **Server**: Uvicorn
- **ML / Data**: Scikit-Learn (Random Forest, Extra Trees, Isolation Forest), NumPy, Pandas, Joblib
- **Database & ORM**: PostgreSQL 14+, SQLAlchemy 2.0+, Psycopg2
- **Auth & Crypto**: Python-Jose (JWT HS256), Passlib (Bcrypt)

### Frontend
- **Framework**: React 18 with TypeScript
- **Bundler & Tooling**: Vite 6, PostCSS, Autoprefixer
- **Styling**: Tailwind CSS (light enterprise theme), CSS Grid
- **Icons & Visuals**: Lucide React, Recharts
- **State & Sync**: Custom React hooks with $O(1)$ ID-based deduplication and automated polling

---

## API Endpoints Reference

| Method | Endpoint | Auth | Description |
|---|---|:---:|---|
| `GET` | `/` | No | Operational dashboard landing or root status |
| `GET` | `/health` | No | Basic server and DB health ping |
| `POST` | `/auth/register` | No | Register new SOC analyst (email, password, role) |
| `POST` | `/auth/login` | No | Authenticate and obtain JWT access token |
| `GET` | `/auth/me` | **JWT** | Return authenticated analyst profile |
| `POST` | `/predict` | **JWT** | Core inference, anomaly detection, risk scoring, response, verification & persistence |
| `GET` | `/events/recent` | **JWT** | Retrieve recent persisted events with verification status (polling feed) |
| `GET` | `/stats` | **JWT** | Aggregate database telemetry (total flows, attacks, benign count) |
| `GET` | `/database/status` | **JWT** | PostgreSQL connection pool and migration diagnostics |
| `GET` | `/prevention/status`| No | Current active blocked and rate-limited tables |
| `GET` | `/model-info` | No | Model ensemble metadata, features, and anomaly parameters |
| `GET` | `/api/status` | No | Operational capabilities and system version |

---

## Setup & Installation

### 1. Prerequisites
- Python 3.10+
- Node.js v18+ & npm
- PostgreSQL 14+ running locally or accessible via network

### 2. Backend Setup
```bash
# Navigate to project root
cd CYVORA-main

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your DATABASE_URL and a secure JWT_SECRET
```

### 3. Database Initialization
Ensure PostgreSQL is running and your target database exists:
```sql
CREATE DATABASE cyvora;
```
Tables will automatically be verified and created on first API startup.

### 4. Running the Backend Server
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

### 5. Running the Frontend Dashboard
```bash
cd frontend
npm install
npm run build   # Production bundle verification
npm run dev     # Start development server at http://localhost:5173
```

---

## Testing & Verification Results

All tests have been executed directly against the live backend and local PostgreSQL instance. Results reflect actual execution:

| Test Suite | File | Verified Result | Status |
|---|---|:---:|:---:|
| **PostgreSQL Persistence** | `test_db_integration.py` | **12 / 12** | **PASS** |
| **JWT Authentication & Protection** | `test_auth.py` | **21 / 21** | **PASS** |
| **Real Event Stream & Deduplication** | `test_real_stream.py` | **11 / 11** | **PASS** |
| **Anomaly & Novelty Detection** | `test_anomaly.py` | **12 / 12** | **PASS** |
| **Context Risk & False-Positive Reduction** | `test_context_risk.py` | **13 / 13** | **PASS** |
| **Response Verification & Enforcement** | `test_response_verification.py` | **12 / 12** | **PASS** |
| **Frontend TypeScript & Vite Build** | `npm run build` | **0 errors / clean bundle** | **PASS** |

To run the complete verification suite locally:
```bash
python test_db_integration.py
python test_auth.py
python test_real_stream.py
python test_anomaly.py
python test_context_risk.py
python test_response_verification.py
```

---

## Deterministic Demo Flow

To demonstrate the full lifecycle of CYVORA during an evaluation or review:

1. **Analyst Login**: Authenticate via the UI or `POST /auth/login` to obtain a session token.
2. **Normal Flow Ingestion**: Send a standard HTTP flow (`Destination Port: 80`, standard packet sizes).
   - *Result*: Classification = `BENIGN`, Anomaly = Low, Risk = Low, Policy = `ALLOW`, Verification = `NOT_APPLICABLE`. Stored in DB.
3. **Attack Flow Ingestion**: Send a high-volume burst vector (e.g., DoS or Patator profile).
   - *Result*: Classification = Attack type, Severity = `HIGH`/`CRITICAL`, Policy = `BLOCK`. Source IP placed in active block list.
4. **Response Verification Asserted**:
   - System queries in-memory block table, confirms active TTL, returns `VERIFIED` status, and logs `RESPONSE_VERIFIED` to PostgreSQL `audit_logs`.
5. **Replay Enforcement Test**: Send another request immediately from the same blocked source IP.
   - *Result*: Immediately rejected with `HTTP 403 Forbidden` (Attacker is locked out).
6. **Novelty Outlier Test**: Send uncalibrated statistical outlier traffic with non-matching flags.
   - *Result*: Anomaly detector triggers ($\ge 0.60$), novelty label = `UNKNOWN_ANOMALOUS`. System escalates policy to `ALERT` for monitoring without blind hard-blocking.
7. **SOC Dashboard Sync**: Frontend poll captures the new events with zero duplicates via $O(1)$ Set deduplication.

---

## Project Status: Implemented vs. Future Work

### Currently Implemented in Prototype
- [x] Supervised V21.1 Tree Ensemble (Random Forest + Extra Trees + Web Specialist)
- [x] Unsupervised Isolation Forest for anomaly and novelty detection
- [x] Deterministic contextual risk engine with 10-minute sliding window
- [x] False-positive reduction with normal traffic concurrence indicators
- [x] Deterministic response policy engine (`ALLOW`, `ALERT`, `RATE_LIMIT`, `BLOCK`)
- [x] Application-level enforcement tables with configurable TTL expiration
- [x] Post-execution response verification and evidence gathering
- [x] PostgreSQL atomic transaction persistence across 5 relational tables
- [x] JWT authentication (HS256) and bcrypt password hashing
- [x] Single-pane-of-glass SOC frontend with live stream polling and $O(1)$ deduplication
- [x] Automated test suites covering all security, persistence, and inference workflows

### Future Production Integrations
- [ ] **Kernel / Firewall Enforcement**: Moving beyond application-level blocking to Linux `nftables`/`iptables` and eBPF/XDP packet drop at the network interface layer.
- [ ] **Hardware Acceleration**: Quantization of tabular tree inference using ONNX Runtime or Treelite for multi-gigabit throughput line rates.
- [ ] **Distributed SIEM Exporters**: Streaming PostgreSQL CDC (Change Data Capture) via Debezium to Apache Kafka or enterprise SIEMs (Splunk / Elastic).
- [ ] **Active Directory / LDAP Integration**: Enterprise identity federation via OAuth2 / OIDC in place of standalone local user management.

---

## Limitations

- **Defensive Actions & Infrastructure**: Defensive actions (`BLOCK`/`RATE_LIMIT`) are enforced safely at the application/API level, not via real network infrastructure. System-activity and authentication-log monitoring are architecturally supported but out of scope for this MVP; network events and security alerts are fully implemented.
- **Prototype Enforcement Scope**: In the current implementation, blocking and rate limiting are enforced at the application/API layer. Sources sending traffic outside the API ingest port are not intercepted at the OS kernel or border router level.
- **Dataset Grounding**: Models are calibrated on standard network flow characteristics (flow durations, packet distributions, header lengths). Environments with proprietary encrypted protocols require domain-specific feature extraction.
- **Single-Node Persistence**: PostgreSQL transactions run against a centralized database instance; high-availability multi-region clustering is not included in the baseline prototype.

---

## Development Team & Buildathon 2026

**CYVORA Engineering Team**
- Engineered for **BUILDATHON 2026**
- Core Focus: High-Reliability Deterministic AI Defense Architecture

---
*CYVORA: Measurable, Auditable, Verifiable Cyber Intelligence.*

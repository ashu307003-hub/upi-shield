# UPI Shield — Defensive Payment-Brand Abuse Detection

UPI Shield is an end-to-end defensive platform for discovering, collecting, scoring and investigating suspected fake UPI/payment pages and applications in **authorized environments only**.

## Current working pipeline

```text
Authorized URL / analyst screenshot
        ↓
Discovery / Capture
        ↓
Screenshot + DOM + network evidence
        ↓
Visual pHash + optional OCR
        ↓
Behavioral DOM analysis
        ↓
URL + DNS + TLS + RDAP intelligence
        ↓
Explainable multi-signal risk score
        ↓
PostgreSQL detection record
        ↓
Neo4j infrastructure observation
        ↓
Analyst dashboard / campaign graph
        ↓
PDF evidence / takedown report
        ↓
Labelled evaluation metrics
```

## Stack

- **Frontend:** Next.js 14, React 18, TypeScript, D3
- **API:** FastAPI, Pydantic
- **Database:** PostgreSQL 16 / SQLAlchemy async
- **Graph:** Neo4j 5
- **Queue/cache:** Redis 7 / Celery scaffold
- **Capture:** Playwright
- **Detection:** pHash, OCR when available, DOM/behavioral signals, URL/DNS/TLS/RDAP intelligence
- **Reports:** ReportLab

## Start locally

### 1. Infrastructure

```powershell
docker compose up -d
docker compose ps
```

### 2. Environment

```powershell
Copy-Item .env.example .env
```

Keep the local development credentials in the example only for local development. Use strong secrets outside a disposable development environment.

### 3. Backend

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-ml.txt
python -m playwright install chromium
python -m uvicorn backend.main:app --reload
```

Open `http://localhost:8000/docs`.

### 4. Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

## Safe end-to-end demo

The repository includes a synthetic local training page at:

```text
data/test-pages/upi-payment-simulation.html
```

Serve it locally in a separate terminal:

```powershell
python -m http.server 8765 --directory data/test-pages --bind 127.0.0.1
```

Then use the dashboard target:

```text
http://127.0.0.1:8765/upi-payment-simulation.html
```

The page contains synthetic training-only fields and must never be used with real credentials. UPI Shield's crawl allowlist defaults to localhost/127.0.0.1 so accidental remote crawling is not enabled by default.

## Main API

- `GET /health` — service health
- `GET /detections` — detection queue
- `POST /captures` — authorized capture + scoring
- `POST /analyze-upload` — screenshot-only analyst analysis
- `POST /discover` — authorized discovery queue ingestion
- `POST /apps/inspect` — safe static APK metadata inspection
- `GET /graph` — Neo4j/fallback graph projection
- `POST /graph/observations` — infrastructure observation ingestion
- `GET /evaluation` — labelled precision/recall/F1/FPR
- `GET /detections/{id}` — evidence detail
- `GET /detections/{id}/report` — PDF evidence report

## Risk model

The baseline score combines:

- visual similarity: 45%
- behavioral indicators: 35%
- domain intelligence: 20%

The dashboard exposes component scores and reasons so an analyst can challenge or validate a verdict. A single indicator is not treated as proof of maliciousness.

## Security boundary

Only crawl or analyze systems where you have authorization or where the activity is explicitly permitted. Do not enter, collect, or transmit real UPI PINs, OTPs, banking passwords, session cookies, payment credentials or funds. Treat collected indicators as sensitive threat-intelligence data and protect access to them.

## Production roadmap

1. Add authenticated analyst accounts and RBAC.
2. Move captures/evidence to object storage with signed URLs.
3. Run Playwright in an isolated worker sandbox with egress controls.
4. Add CT/TI ingestion adapters behind a queue.
5. Add calibrated ML/embedding models and a labelled training set.
6. Add domain/hosting/ASN enrichment providers under approved API contracts.
7. Add campaign clustering jobs over Neo4j observations.
8. Add audit logs, retention policies and evidence integrity hashes.
9. Add CI tests, container image scanning and deployment manifests.

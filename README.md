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

- **Frontend:** Next.js 16.4.3, React 18, TypeScript, D3
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

The frontend opens at the sign-in screen. Create an analyst account with a name,
email address, country-coded mobile number, and password. The account stays
inactive until its email is confirmed. For local development, SMTP messages are
captured by Mailpit at `http://localhost:8025`; open the confirmation message
there and follow its link. Login notifications are also sent through SMTP.

To send mail through Brevo instead of the local Mailpit inbox, create a Brevo
account, verify a sender address, and get the SMTP login and SMTP key from the
Brevo SMTP settings. Set `SMTP_HOST=smtp-relay.brevo.com`, `SMTP_PORT=587`,
`SMTP_USERNAME` to the Brevo SMTP login, `SMTP_PASSWORD` to the SMTP key,
`SMTP_STARTTLS=true`, `SMTP_USE_SSL=false`, and `REPORT_FROM_EMAIL` to the
verified sender address in `.env`. Restart the backend after changing these
settings. Keep the SMTP key private; it is not the Brevo API key or account
password.

Accounts are stored in PostgreSQL, passwords are scrypt-hashed, and browser
sessions use a seven-day HttpOnly cookie. Set `ADMIN_EMAILS` to a comma-separated
list of verified email addresses that should access `/admin`. The dashboard and
captured evidence require an active session, and admin records require an
allowlisted session. Page-view analytics store aggregate route counts only;
they do not persist visitor IP addresses, cookies, or identifiers.

Activity events are retained for `ACTIVITY_RETENTION_DAYS` (180 by default).
Account profiles, detection records, screenshots, and evidence files are not
deleted by that activity-log cleanup and require a separate retention policy.
The API can start when Neo4j is offline; graph features remain unavailable until
Neo4j is running.
Registration is open to anyone who can reach the application, so deploy behind
HTTPS, set `FRONTEND_ORIGINS` to the exact frontend origin, and add an invitation
or organization policy before exposing it publicly.

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

The API reuses its Chromium browser process between captures while keeping each
capture in a separate browser context. DNS, TLS, and RDAP enrichment also run
concurrently because they are independent lookups.

Active DNS, TLS, and RDAP lookups run only for URLs inside `CRAWL_ALLOWLIST`.
Screenshot uploads for other URLs still receive visual and lexical analysis,
without making network connections to the submitted host. Captured HTML
evidence is served as a download rather than executable page content.

## Main API

- `POST /auth/register` — create an account and send an email confirmation link
- `POST /auth/verify` — confirm an account email address
- `POST /auth/resend-verification` — request another confirmation email
- `POST /auth/login` — sign in and start a session
- `GET /auth/me` — read the active analyst session
- `POST /auth/logout` — revoke the current session
- `POST /analytics/visit` — record an aggregate page-view route
- `GET /admin/overview` — read admin-only account, visit, login, and feature metrics
- `GET /admin/users` — read admin-only account profiles and login counts
- `GET /admin/activity` — read admin-only audit events and stored results
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

`POST /discover` accepts a `source` label of up to 100 characters (default:
`analyst_report`). Custom labels are supported; surrounding whitespace is
trimmed and control characters are rejected. The `urls` must still be within
the configured `CRAWL_ALLOWLIST`.

## Risk model

The baseline score combines:

- visual similarity: 45%
- behavioral indicators: 35%
- domain intelligence: 20%

The dashboard exposes component scores and reasons so an analyst can challenge or validate a verdict. A single indicator is not treated as proof of maliciousness.

## Security boundary

Only crawl or analyze systems where you have authorization or where the activity is explicitly permitted. Do not enter, collect, or transmit real UPI PINs, OTPs, banking passwords, session cookies, payment credentials or funds. Treat collected indicators as sensitive threat-intelligence data and protect access to them.

## Production roadmap

1. Move captures/evidence to object storage with signed URLs.
2. Run Playwright in an isolated worker sandbox with egress controls.
3. Add CT/TI ingestion adapters behind a queue.
4. Add calibrated ML/embedding models and a labelled training set.
5. Add domain/hosting/ASN enrichment providers under approved API contracts.
6. Add campaign clustering jobs over Neo4j observations.
7. Define account, detection, and evidence retention policies.
8. Add evidence integrity hashes, container image scanning, and deployment manifests.

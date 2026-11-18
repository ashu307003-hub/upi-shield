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

### Quick bootstrap

Use the project bootstrap helper to validate the environment and start the local infrastructure:

```powershell
python scripts/start_local.py --check
python scripts/start_local.py
```

The helper creates `.env` from `.env.example` if needed, checks that Docker is available, starts the Compose services, and prints the next commands for the backend and frontend.

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
Each successful sign-in email includes the UTC login time and source IP address.
Use **Forgot password?** on the sign-in screen to email a one-time reset link;
the same flow is available from the Android sign-in screen. Reset the password
in the web page opened by the link, or enter the one-time code from the email
in the Android app. Then sign in again with the new password.
When running behind a reverse proxy, configure Uvicorn's
`--forwarded-allow-ips` with only the trusted proxy addresses and configure the
proxy to overwrite forwarded client-IP headers.

### Chrome / Edge click-time link protection

The unpacked extension in `extension/` pauses clicked external web links and
shows a report before opening them. The API checks saved threat-intelligence
indicators, prior UPI Shield detections, and URL-text heuristics; the report
includes a 0–100 **risk score, not a probability**, and the signals that
contributed to it. Known or heuristic risk signals produce a warning with a
continue option. A link with no known match is reported as unknown/low-signal,
not as confirmed safe or not fraudulent. This click-time check does not inspect
the page contents, payment request, QR code, or payee/recipient and cannot stop
or reverse a payment.

Checks require a signed-in dashboard session and an extension origin allowed by
the configured API. Clicked URLs are sent to the configured UPI Shield API for
reputation lookup; only use an API instance you trust.

1. In Chrome or Edge, open `chrome://extensions` or `edge://extensions`, enable
   Developer mode, and choose **Load unpacked**. Select the repository's
   `extension` folder.
2. Copy the extension ID shown by the browser and allow its origin in the
   backend: set `BROWSER_EXTENSION_ORIGINS=chrome-extension://<extension-id>`
   in the backend environment. For Edge, use its extension ID; if using both
   browsers, comma-separate both extension origins. Restart or redeploy the API.
3. Open the extension popup and enter the trusted API base address (for example,
   `http://localhost:8000` locally or the API's HTTPS URL when deployed). Save
   it, then sign in to the dashboard connected to that same backend.

The extension checks clicked external anchor links in Chrome/Edge. Directly
typing a URL, opening a link inside another desktop/mobile application, and
links not represented by ordinary page anchors are not checked. Cross-
application payment protection needs a separate platform-specific app or OS
integration.

### Android mobile app

The Expo app in `mobile/` supports analyst sign-in, a dashboard with recent
detections, pasted/shared links, and QR scanning. QR-embedded web links use the
URL reputation check; supported `upi://pay` QR codes check the payee address
against threat-intelligence data. The report shows a risk signal score, not a
probability, and an unmatched payee is not verified safe. The app does not
initiate payments, inspect bank-app transactions, or verify a displayed payee
name with the payment network. One-time mobile link and QR checks are shown on
the phone but are not added to the saved detection queue.

The phone must use a publicly reachable HTTPS backend; `localhost` on Android
means the phone, not the development PC. Create and verify the analyst account
through the web dashboard first. In the app, enter the backend's HTTPS base URL
and sign in. The mobile app stores the session token with Android secure
storage.

#### Deploying on Render

The root `Dockerfile` packages the FastAPI backend and Chromium used by browser
checks. The repository includes `render.yaml` for a Render Blueprint containing
the API web service and PostgreSQL database.

In Render, create a new Blueprint from this repository and review the environment
variables. Set `FRONTEND_ORIGINS` to the exact HTTPS web-dashboard origin and
set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
`SMTP_STARTTLS`, `SMTP_USE_SSL`, and `REPORT_FROM_EMAIL` to working mail
credentials. Registration verification, sign-in notifications, and password
reset require SMTP. The first `FRONTEND_ORIGINS` entry is used for links sent
by email, so it must be the reachable dashboard URL rather than `localhost`.
Do not put secrets in source control.

PostgreSQL is required. Neo4j and Redis can be omitted for an initial mobile
test, but graph features and background crawl jobs will be unavailable. After
the API deploys, check `https://<api-service>.onrender.com/health`, then set
`NEXT_PUBLIC_API_URL` to the API origin when building the dashboard and enter
the same origin alone (without `/health`) in the mobile app.

To build a personal-test APK on Windows with Android Studio and its SDK installed:

```powershell
cd mobile
npm install
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
npm run build:android:release
```

The APK is written to
`mobile\android\app\build\outputs\apk\release\app-release.apk`. It is signed
with the local Android debug key for personal testing only. Do not distribute
this APK publicly; a production release requires a private signing key and a
secure distribution channel. Install it on a connected Android phone with
`adb install -r` and that path, or copy the APK to the phone and open it.

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

Registration and sign-in require an account type: student or working
professional. Student profiles include their institution, academic session,
department, course, year of study, and a required PNG, JPEG, or PDF student ID
card upload (maximum 5 MB). Professional profiles include employer, department,
job title, employment type, and employee ID. The profile page shows the signed-in
user's details and provides a private student ID download. ID cards are stored
under `data/private_ids/`, excluded from version control, and served only to
their signed-in owner. The sidebar provides profile, sign-out, and switch-account
actions; switching accounts signs out before returning to sign-in.

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
- `POST /auth/forgot-password` — request a one-time password reset email
- `POST /auth/reset-password` — set a new password using the emailed token or code
- `POST /auth/login` — sign in and start a session
- `GET /auth/me` — read the active analyst session
- `POST /auth/logout` — revoke the current session
- `POST /mobile/auth/login` — sign in to the Android app and issue a bearer session
- `POST /mobile/auth/logout` — revoke an Android app bearer session
- `GET /mobile/dashboard` — authenticated mobile dashboard summary
- `POST /mobile/check-qr` — assess QR web links or UPI payee indicators
- `POST /analytics/visit` — record an aggregate page-view route
- `GET /admin/overview` — read admin-only account, visit, login, and feature metrics
- `GET /admin/users` — read admin-only account profiles and login counts
- `GET /admin/activity` — read admin-only audit events and stored results
- `GET /health` — service health
- `GET /detections` — detection queue
- `POST /browser/check` — authenticated URL reputation check for the extension
- `POST /captures` — authorized capture + scoring
- `POST /analyze-upload` — screenshot-only analyst analysis
- `POST /discover` — authorized discovery queue ingestion
- `POST /apps/inspect` — safe static APK metadata inspection
- `GET /graph` — Neo4j/fallback graph projection
- `POST /graph/observations` — infrastructure observation ingestion
- `GET /evaluation` — labelled precision/recall/F1/FPR
- `GET /reports?section=all` — download a full PDF report; choose `summary`,
  `checks`, `brands`, `evaluation`, or `connections` for a section report
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

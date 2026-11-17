# Deploying the UPI Shield mobile API on Railway

The root `Dockerfile` builds the FastAPI backend and installs Chromium for
browser checks. Deploy the repository from its root so Railway can find
`railway.json` and the Dockerfile.

## Railway services

For an initial mobile test, create one API service from the repository and one
PostgreSQL service. The hosted database starts empty. Neo4j and Redis can be
omitted initially; graph features and background crawl jobs will be unavailable.

In the API service's Variables panel:

- Set `DATABASE_URL` to a Railway reference variable such as
  `${{Postgres.DATABASE_URL}}`. The backend normalizes Railway's PostgreSQL URL
  for its async driver.
- Set `FRONTEND_ORIGINS` to the exact origin of the web dashboard. For a local
  dashboard during setup, this can be `http://localhost:3000`.
- Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
  `SMTP_STARTTLS`, `SMTP_USE_SSL`, and `REPORT_FROM_EMAIL` for a verified mail
  sender. Registration verification and sign-in notifications require SMTP.

Keep all credentials in Railway Variables, never in the repository. Generate a
Railway public domain for the API, then verify `https://YOUR-DOMAIN/health`
returns a healthy response.

## Create an account and sign in

The hosted database does not contain local accounts. Configure the web
dashboard to use the Railway API by setting `NEXT_PUBLIC_API_URL` to the API's
base HTTPS URL, then create and verify an account through the dashboard. The
dashboard origin must be included in `FRONTEND_ORIGINS`. Enter the API base URL
alone in the Android app; do not append `/health` or another route.

Registration is currently open to anyone who can reach the API. Monitor
resource usage and billing, and restrict registration before using the service
for a wider audience.

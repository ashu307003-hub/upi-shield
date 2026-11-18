# Deploying UPI Shield on Render

## 1. Create the Blueprint

Push the repository to GitHub, open the Render dashboard, choose **New > Blueprint**,
and connect this repository. Render reads `render.yaml` and creates:

- `upi-shield-api` as a Docker web service
- `upi-shield-db` as PostgreSQL

The API Dockerfile health check uses `/health`.

## 2. Configure the API

Set these environment variables in the `upi-shield-api` service:

- `FRONTEND_ORIGINS`: exact HTTPS origin of the deployed Next.js dashboard
- `BROWSER_EXTENSION_ORIGINS`: comma-separated extension origins, if used
- `SMTP_HOST`: SMTP server hostname
- `SMTP_PORT`: normally `587`
- `SMTP_USERNAME`: SMTP login
- `SMTP_PASSWORD`: SMTP password or app-specific key
- `SMTP_STARTTLS`: `true`
- `SMTP_USE_SSL`: `false`
- `REPORT_FROM_EMAIL`: verified sender address
- `ADMIN_EMAILS`: comma-separated verified admin addresses

`DATABASE_URL` is supplied by Render from the PostgreSQL database. The backend
converts standard `postgres://` and `postgresql://` URLs to the asyncpg driver.

## 3. Deploy and verify the API

After the first deployment, open:

```text
https://<api-service>.onrender.com/health
```

Confirm `database` and `postgres` are healthy. Then open `/docs` and verify the
password reset routes are present.

## 4. Deploy the dashboard

Create a separate Render web service for `frontend/`:

- Root directory: `frontend`
- Build command: `npm ci && npm run build`
- Start command: `npm start`
- Environment variable: `NEXT_PUBLIC_API_URL=https://<api-service>.onrender.com`

Redeploy the dashboard whenever `NEXT_PUBLIC_API_URL` changes. Set
`FRONTEND_ORIGINS` on the API to the exact dashboard origin, for example
`https://upi-shield-web.onrender.com`.

## 5. Configure clients

- Enter the API origin in the browser-extension popup.
- Enter the API origin alone in the Android app.
- Do not append `/health`, `/docs`, or another route.
- Add the extension ID origin to `BROWSER_EXTENSION_ORIGINS`.

## Password reset

Forgot-password emails require a working SMTP provider. The reset endpoint
returns a privacy-preserving generic response, but a real account receives an
email containing a one-time reset link or code. Open the web reset page on the
deployed dashboard; in the Android app, enter the one-time code from the email.

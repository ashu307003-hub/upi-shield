# Deploying UPI Shield on Render

## 1. Create the Blueprint

Push the repository to GitHub, open the Render dashboard, choose **New > Blueprint**,
and connect this repository. Render reads `render.yaml` and creates:

- `upi-shield-api` as a Docker web service
- `upi-shield-web` as a Next.js web service
- `upi-shield-db` as PostgreSQL

The API Dockerfile health check uses `/health`. The website is built from
`frontend/` and is configured to use the API's public URL.

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

## 4. Configure and verify the dashboard

After Render creates both web services, copy the dashboard's public HTTPS
origin into `FRONTEND_ORIGINS` on the API service and redeploy the API. The
website service is configured with `NEXT_PUBLIC_API_URL`; if the API's public
hostname differs from the value in `render.yaml`, update that variable and
redeploy the website.

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

# Xero Invoice Automation

FastAPI service that listens for Xero webhooks and automatically sets line-item descriptions on invoices using the template:

```
Fortnightly clean — Service date: {D Month YYYY}
```

The description is only written if it does not already contain the formatted date, making updates idempotent.

---

## Environment variables

| Variable | Description |
|---|---|
| `XERO_CLIENT_ID` | OAuth 2.0 client ID from the Xero developer portal |
| `XERO_CLIENT_SECRET` | OAuth 2.0 client secret from the Xero developer portal |
| `XERO_WEBHOOK_KEY` | Webhook signing key from the Xero developer portal |
| `XERO_REDIRECT_URI` | Must match the redirect URI registered in Xero (e.g. `https://toolshed.berrybright.com.au/callback`) |
| `DATABASE_URL` | PostgreSQL connection string (asyncpg-compatible, e.g. `postgresql://user:pass@host:5432/dbname`) |

---

## Database setup

Run the following against the existing Postgres instance **once** before first deploy:

```sql
-- Main table
CREATE TABLE xero_tokens (
    id           SERIAL PRIMARY KEY,
    access_token  TEXT        NOT NULL,
    refresh_token TEXT        NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    tenant_id     TEXT        NOT NULL,
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Dedicated low-privilege user
CREATE USER xero_svc WITH PASSWORD '<strong-password>';
GRANT CONNECT ON DATABASE <dbname> TO xero_svc;
GRANT USAGE ON SCHEMA public TO xero_svc;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE xero_tokens TO xero_svc;
GRANT USAGE, SELECT ON SEQUENCE xero_tokens_id_seq TO xero_svc;
```

Set `DATABASE_URL` to use `xero_svc` credentials so the running process only has access to the `xero_tokens` table.

---

## One-time OAuth flow

After the service is deployed and all environment variables are set:

1. Open `https://<your-domain>/auth` in a browser.
2. Log in to Xero and authorise the application.
3. You are redirected to `/callback`, which exchanges the code for tokens and stores them in the database.
4. The service is now ready to process webhooks.

To re-authenticate at any time (e.g. after a revocation), repeat from step 1.

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth` | Starts Xero OAuth 2.0 flow, redirects to Xero login |
| `GET` | `/callback` | Handles OAuth redirect; stores tokens to `xero_tokens` |
| `POST` | `/webhook/xero` | Receives Xero webhook payloads; validates HMAC-SHA256 signature; patches invoice descriptions |
| `GET` | `/health` | Returns `{"status": "ok"}`; used by Railway health checks |

---

## Webhook signature validation

Every inbound `POST /webhook/xero` request is validated before processing:

1. Raw request body is read with `await request.body()`.
2. `HMAC-SHA256(XERO_WEBHOOK_KEY, body)` is computed and base64-encoded.
3. The result is compared (constant-time) against the `x-xero-signature` header.
4. A `401` is returned immediately if validation fails.

---

## Token refresh

Before every Xero API call the service checks whether the stored access token expires within **60 seconds**. If so, it refreshes using the stored refresh token and writes the new tokens back to `xero_tokens`.

---

## Local development

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export XERO_CLIENT_ID=...
export XERO_CLIENT_SECRET=...
export XERO_WEBHOOK_KEY=...
export XERO_REDIRECT_URI=http://localhost:8000/callback
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/xero

uvicorn main:app --reload
```

---

## Railway deployment

The service is deployed as part of the **sparkling-creativity** Railway project and uses the existing Postgres instance in that project.

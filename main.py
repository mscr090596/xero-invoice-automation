import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse

from xero_python.accounting import AccountingApi
from xero_python.accounting.models import Invoice, Invoices, LineItem
from xero_python.api_client import ApiClient
from xero_python.api_client.configuration import Configuration

# ── Config ────────────────────────────────────────────────────────────────────
XERO_CLIENT_ID = os.environ["XERO_CLIENT_ID"]
XERO_CLIENT_SECRET = os.environ["XERO_CLIENT_SECRET"]
XERO_WEBHOOK_KEY = os.environ["XERO_WEBHOOK_KEY"]
XERO_REDIRECT_URI = os.environ["XERO_REDIRECT_URI"]
DATABASE_URL = os.environ["DATABASE_URL"]

XERO_AUTH_URL = "https://login.xero.com/identity/connect/authorize"
XERO_TOKEN_URL = "https://identity.xero.com/connect/token"
XERO_CONNECTIONS_URL = "https://api.xero.com/connections"
XERO_SCOPES = "openid profile email accounting.transactions accounting.settings offline_access"

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="Xero Invoice Automation")
_pool: Optional[asyncpg.Pool] = None
_executor = ThreadPoolExecutor(max_workers=4)


@app.on_event("startup")
async def startup():
    global _pool
    _pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)


@app.on_event("shutdown")
async def shutdown():
    if _pool:
        await _pool.close()


# ── Token helpers ─────────────────────────────────────────────────────────────

async def _load_token() -> Optional[dict]:
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT access_token, refresh_token, expires_at, tenant_id "
            "FROM xero_tokens ORDER BY updated_at DESC LIMIT 1"
        )
        return dict(row) if row else None


async def _save_token(
    access_token: str,
    refresh_token: str,
    expires_at: datetime,
    tenant_id: str,
):
    async with _pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("DELETE FROM xero_tokens")
            await conn.execute(
                "INSERT INTO xero_tokens (access_token, refresh_token, expires_at, tenant_id) "
                "VALUES ($1, $2, $3, $4)",
                access_token,
                refresh_token,
                expires_at,
                tenant_id,
            )


async def _do_refresh(refresh_token: str, tenant_id: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            XERO_TOKEN_URL,
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            auth=(XERO_CLIENT_ID, XERO_CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=data["expires_in"])
    await _save_token(data["access_token"], data["refresh_token"], expires_at, tenant_id)
    return {
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "expires_at": expires_at,
        "tenant_id": tenant_id,
    }


async def get_valid_token() -> dict:
    token = await _load_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail="Not authenticated with Xero. Visit /auth to start the OAuth flow.",
        )
    expires_at = token["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at - datetime.now(timezone.utc) < timedelta(seconds=60):
        token = await _do_refresh(token["refresh_token"], token["tenant_id"])
    return token


# ── OAuth endpoints ───────────────────────────────────────────────────────────

@app.get("/auth")
async def auth():
    """Start the Xero OAuth 2.0 flow."""
    params = {
        "response_type": "code",
        "client_id": XERO_CLIENT_ID,
        "redirect_uri": XERO_REDIRECT_URI,
        "scope": XERO_SCOPES,
        "state": secrets.token_urlsafe(16),
    }
    return RedirectResponse(XERO_AUTH_URL + "?" + urllib.parse.urlencode(params))


@app.get("/callback")
async def callback(code: str, state: Optional[str] = None):
    """Handle the OAuth redirect; exchange code for tokens and persist them."""
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            XERO_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": XERO_REDIRECT_URI,
            },
            auth=(XERO_CLIENT_ID, XERO_CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        conn_resp = await client.get(
            XERO_CONNECTIONS_URL,
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
        conn_resp.raise_for_status()
        connections = conn_resp.json()

    if not connections:
        raise HTTPException(status_code=400, detail="No Xero organisations are connected.")

    tenant_id = connections[0]["tenantId"]
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])
    await _save_token(
        token_data["access_token"],
        token_data["refresh_token"],
        expires_at,
        tenant_id,
    )
    return {
        "status": "authenticated",
        "tenant_id": tenant_id,
        "organisation": connections[0].get("tenantName"),
    }


# ── Webhook ───────────────────────────────────────────────────────────────────

def _valid_signature(body: bytes, header: str) -> bool:
    mac = hmac.new(XERO_WEBHOOK_KEY.encode(), body, hashlib.sha256).digest()
    return hmac.compare_digest(base64.b64encode(mac).decode(), header)


def _fmt_xero_date(date_val) -> str:
    """Return 'D Month YYYY' from a Xero date value (datetime or /Date(ms)/ string)."""
    if isinstance(date_val, datetime):
        dt = date_val if date_val.tzinfo else date_val.replace(tzinfo=timezone.utc)
    elif isinstance(date_val, str) and date_val.startswith("/Date("):
        inner = date_val[6:-2]
        ms_str = inner.split("+")[0] if "+" in inner else inner.split("-")[0]
        dt = datetime.fromtimestamp(int(ms_str) / 1000, tz=timezone.utc)
    else:
        dt = datetime.fromisoformat(str(date_val).replace("Z", "+00:00"))
    return f"{dt.day} {dt.strftime('%B')} {dt.year}"


async def _process_invoice(invoice_id: str, token: dict) -> None:
    loop = asyncio.get_running_loop()
    config = Configuration()
    config.access_token = token["access_token"]
    api_client = ApiClient(configuration=config)
    accounting = AccountingApi(api_client)
    tenant_id = token["tenant_id"]

    invoices_resp = await loop.run_in_executor(
        _executor,
        lambda: accounting.get_invoice(xero_tenant_id=tenant_id, invoice_id=invoice_id),
    )
    if not invoices_resp.invoices:
        return

    invoice = invoices_resp.invoices[0]
    if not invoice.date:
        return

    formatted_date = _fmt_xero_date(invoice.date)
    target_suffix = f"Service date: {formatted_date}"

    needs_update = False
    patched_items = []

    for item in invoice.line_items or []:
        desc = item.description or ""
        if target_suffix in desc:
            patched_items.append(item)
        else:
            needs_update = True
            patched_items.append(
                LineItem(
                    line_item_id=item.line_item_id,
                    description=f"Fortnightly clean \u2014 {target_suffix}",
                    quantity=item.quantity,
                    unit_amount=item.unit_amount,
                    account_code=item.account_code,
                    tax_type=item.tax_type,
                )
            )

    if not needs_update:
        return

    patch = Invoices(
        invoices=[Invoice(invoice_id=invoice.invoice_id, line_items=patched_items)]
    )
    await loop.run_in_executor(
        _executor,
        lambda: accounting.update_invoice(
            xero_tenant_id=tenant_id,
            invoice_id=invoice_id,
            invoices=patch,
        ),
    )
    print(f"[invoice] updated {invoice_id} with '{target_suffix}'")


@app.post("/webhook/xero")
async def webhook_xero(request: Request):
    """Receive Xero webhook events, validate signature, patch invoice descriptions."""
    body = await request.body()
    sig = request.headers.get("x-xero-signature", "")

    if not _valid_signature(body, sig):
        return Response(status_code=401)

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return Response(status_code=200)

    for event in payload.get("events", []):
        if event.get("eventCategory") != "INVOICE":
            continue
        if event.get("eventType") not in ("CREATE", "UPDATE"):
            continue
        invoice_id = event.get("resourceId")
        if not invoice_id:
            continue
        try:
            token = await get_valid_token()
            await _process_invoice(invoice_id, token)
        except Exception as exc:
            print(f"[webhook] error processing invoice {invoice_id}: {exc}")

    return Response(status_code=200)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}

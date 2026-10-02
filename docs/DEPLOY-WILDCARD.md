# Deploy wildcard `*.securepublish.work`

**Status (2026-10-02):** wildcard **LIVE** — route `*.securepublish.work/*` → Worker `secure-publish` (DNS Worker record proxied). Apex/`www` stay on Pages (landing). Console: `app.securepublish.work`.

Confirmed: `GET https://demo.securepublish.work/{panel-id}` without session → **302** login (panel HTML not leaked).

## 1. Attach the Worker to the zone

**Done via dashboard** (token may lack Workers Routes API scope):

1. [Workers & Pages](https://dash.cloudflare.com) → worker **`secure-publish`**.
2. **Settings → Domains & Routes → Add**  
   - Custom Domain / route: `*.securepublish.work/*`  
   - Apex/`www` remain on **Pages** for the landing; panel hosts use the wildcard.
3. Confirm CF created the proxy records in DNS.

**Or wrangler** (requires zone/routes permission on the API token):

Uncomment is already applied in `packages/edge/wrangler.toml` (`[[routes]]`). Redeploy if you change it:

```bash
cd packages/edge
npx wrangler deploy
```

Fallback host still up: `https://secure-publish.clovist.workers.dev` (`workers_dev = true`). Same Worker = same `/api/*` and panel routes.

## 2. Console origin + CORS

Set Worker var `CONSOLE_ORIGIN` (comma-separated, exact origins):

```text
https://app.securepublish.work,https://secure-publish-app.pages.dev,http://127.0.0.1:8765
```

```bash
cd packages/edge
npx wrangler deploy   # picks up [vars] from wrangler.toml
```

OAuth callbacks stay on the **Worker** host: `/_auth/callback/{provider}` (Google on workers.dev and on `*.securepublish.work` if redirect URIs include both).

### `SP_API_BASE` (Cameron / console)

Do **not** change Cameron’s `SP_API_BASE` without coordinating. Either works (same Worker):

| Base | Notes |
|------|--------|
| `https://secure-publish.clovist.workers.dev` | Current prod default; keep until console migrates |
| `https://demo.securepublish.work` (or any `*.securepublish.work`) | Same `/api/*`; same-site with `app.securepublish.work` (eTLD+1) |

Cookie checklist: [security-cookie-cross-origin.md](./security-cookie-cross-origin.md). While console hits **workers.dev**, keep **SameSite=None; Secure**. If console API moves to `*.securepublish.work`, prefer **SameSite=Lax** + `Domain=.securepublish.work`.

## 3. CLI base URL

| Phase | `SECURE_PUBLISH_BASE_URL` | Example panel URL |
|-------|---------------------------|-------------------|
| **Wildcard (default now)** | `https://demo.securepublish.work` (interim tenant) or `https://{slug}.securepublish.work` | `https://demo.securepublish.work/{id}` |
| Fallback | `https://secure-publish.clovist.workers.dev` | `https://secure-publish.clovist.workers.dev/{id}` |

```bash
export SECURE_PUBLISH_BASE_URL=https://demo.securepublish.work
# or tenant slug when reserved:
# export SECURE_PUBLISH_BASE_URL=https://acme.securepublish.work
# fallback:
# export SECURE_PUBLISH_BASE_URL=https://secure-publish.clovist.workers.dev
```

## 4. Publish E2E checklist (needs `CLOUDFLARE_API_TOKEN`)

Token is issued by John/ops — **never invent or commit secrets**.

```bash
export CLOUDFLARE_API_TOKEN=…          # from John — not in git
export CLOUDFLARE_ACCOUNT_ID=10841252c6d660571d29ceb713026269
export SECURE_PUBLISH_KV_NAMESPACE_ID=46d61ee3d1f7410fa081e383b776934a
export SECURE_PUBLISH_BASE_URL=https://demo.securepublish.work
export SECURE_PUBLISH_COMPANY_DOMAINS=wises.com.br

node packages/cli/bin/secure-publish.js doctor
# expect: token verify OK

node packages/cli/bin/secure-publish.js publish examples/panel-vendas.html \
  --title "E2E wildcard"
# note the printed URL → PANEL_URL

# No session → must NOT serve panel HTML
curl -sI "$PANEL_URL" | head -5
# OAuth mode: HTTP/2 302 → /_auth/login?return_to=…
# /api/me without cookie → 401 {"error":"unauthorized"}
# Body of GET /$PANEL_ID must be empty (0 bytes) before login.

# With SSO session cookie (browser after Google login) → 200 + HTML
```

Proof file after a real run: `E2E-WILDCARD.txt`. Without a token, use mock only:

```bash
SECURE_PUBLISH_MOCK=1 node packages/cli/bin/secure-publish.js doctor
npm run e2e:mock
```

## 5. Still optional / later

- Dedicated `api.securepublish.work` (optional; not required — `/api` already on wildcard Worker)
- Migrate cookie to SameSite=Lax when console API stays on `*.securepublish.work`
- GitHub / Microsoft OAuth apps (V1 = **Google only**)

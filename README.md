# Secure Publish

CLI + skill to publish AI HTML dashboards behind company sign-in.

```text
https://{host}/{panel-id}

# default host:  {slug}.securepublish.work  (wildcard LIVE; demo interim)
# fallback:      secure-publish.clovist.workers.dev
```

- The **URL identifies** the dashboard (KV id). It is **not** a credential.
- **SSO** (Cloudflare Access with Google / Microsoft / GitHub, or Worker OAuth) authenticates the viewer.
- **V1 ACL (Lock A):** after SSO, default access is the tenant’s **email domain** (`OAUTH_ALLOWED_DOMAINS` style). `--to` is an explicit email allowlist. This is **not** Google Workspace / Microsoft Entra / GitHub Org membership — that is a later phase.
- Product UI still says **“toda a empresa” / Company-wide**. CLI metadata mode is `company` (alias `org` accepted by the edge). Docs and errors say **domain**, not org check.

Preferred path for agents: install the skill, then ask it to publish. The console tracks URLs and views; there is no web publish button.

```text
npx skills add https://github.com/clovistx/secure-publish --skill "secure-publish"
```

Then: *Publique este dashboard HTML com Secure Publish.*

> Until Access or Worker OAuth is configured, the Worker **does not serve HTML** (HTTP 403). See [Ligar SSO](#ligar-sso).

## O que é / o que não é

| É | Não é |
|---|--------|
| Publish de HTML na edge (Worker + KV + SSO) | Parser de HTML / framework de dashboard |
| ACL V1 por domínio de e-mail, ou `--to` | Membership de org Workspace / Entra / GitHub Org |
| CLI + skill (agent-first) | Botão “publicar” na web |
| Sessão SSO antes do HTML | Auth por “saber a URL” |

## Security checklist (mock ≠ product)

1. **Mock ≠ SSO.** A tela “Continuar como …” na landing/demo prova o *fluxo*; não autentica ninguém. Nunca diga “login Google/Microsoft/GitHub de verdade” nessa página.
2. **Não imite UI do IdP.** Sem logos, cores ou “janelinha Google”. Use “Continuar como …” genérico + rótulo visível: *Demo do fluxo · não é login de verdade*.
3. **URL do painel não é credencial.** `/{panel-id}` só identifica o HTML no KV. Sem sessão SSO (Access JWT ou cookie OAuth), o Worker responde 403 — mesmo com a URL.
4. **Allowlist de domínio ≠ org membership.** `OAUTH_ALLOWED_DOMAINS` (e-mail `@empresa.com`) ou política Access “emails ending in” é **allowlist de domínio**. Isso **não** verifica membership em org Google Workspace / Entra / GitHub Org. Conta pessoal no mesmo domínio pode passar se a política for só “authenticated” + domínio.
5. **Não claimar:** E2E encryption, compliance/SOC2, “ninguém nunca vaza”, “compatível com IdP X” antes do OAuth/Access desse IdP estar ligado, waitlist que “já salvou o e-mail” sem storage real, `SSO_DEV_BYPASS` / auth mock em produção.

| Controle | O que faz | Limite |
|----------|-----------|--------|
| Só “authenticated” no IdP | Qualquer conta que logar no Google/MS/GitHub | Largo demais pra B2B |
| Allowlist de domínio (`OAUTH_ALLOWED_DOMAINS`) — **default V1** | Só e-mails `@suaempresa.com` após SSO | Não prova conta da org (aliases, freelancers no domínio) |
| `--to` | Só estes e-mails (ainda exige SSO) | Lista explícita, não “toda a empresa” |
| Org / group membership (fase seguinte) | Workspace group, Entra group, GitHub org/team | Conta enterprise de verdade |

## Arquitetura

```text
CLI (securepublish-cli publish [--to])
        │  Cloudflare REST API (KV PUT)   or --mock local store
        ▼
   KV namespace "PANELS"   panel-id → { html, access }
        ▲
        │  binding PANELS
 Cloudflare Access (preferred)  →  login Google/Microsoft/GitHub
        │  Cf-Access-Jwt-Assertion
 Cloudflare Worker
        │
 GET /{panel-id}
   → resolvePanel(id)
   → requireSsoSession()
   → ACL: domain (company) OR email list (--to)
   → text/html
```

## Modelo de acesso

| Peça | Papel |
|------|--------|
| `/{panel-id}` | Identifica *qual* dashboard ler no KV |
| Cloudflare Access (preferido) | Login IdP + JWT `Cf-Access-Jwt-Assertion` |
| OAuth no Worker (alternativa) | Cookie `secure_publish_session` |
| Default sem `--to` | **Company-wide = domínio de e-mail do tenant** |
| `--to a@x,b@y` | Allowlist explícita de e-mails |
| `OAUTH_ALLOWED_DOMAINS` | Domínios do tenant no Worker (ex.: `empresa.com`) |

Metadata `mode` pode ser `company` ou `org`. Os dois significam **domínio**, não checagem de org.

### Modos do Worker (`ssoMode`)

1. **`access`** — `TEAM_DOMAIN` + `POLICY_AUD` → valida JWT Access.
2. **`oauth`** — `SESSION_SECRET` + pelo menos um par `*_CLIENT_ID` / `*_CLIENT_SECRET`.
3. **`none`** — falha fechada: 403 “SSO não configurado”.
4. **`dev-bypass`** — só `SSO_DEV_BYPASS=1` em `wrangler dev` local; **nunca** em produção.

## CLI

Command name: **`securepublish-cli`**. Do **not** `npm install secure-publish` or `npx secure-publish` (unrelated public package). From this repo:

```bash
npx --yes github:clovistx/secure-publish
```

```bash
# default: toda a empresa = mesmo domínio de e-mail do tenant
securepublish-cli publish examples/panel-vendas.html --title "Painel Vendas Q3"

# restringir
securepublish-cli publish examples/panel-ops.html --to ana@empresa.com,bia@empresa.com

securepublish-cli list
securepublish-cli revoke <key>
securepublish-cli doctor
```

Mensagens (PT):

- `Publicado pra **toda a empresa**: {url}`
- `Publicado só para {emails}: {url}`
- Domínio errado: *Seu e-mail não é do domínio desta empresa. Peça acesso ou use a conta corporativa.*
- Sem permissão: *Você está logado, mas não tem permissão neste dashboard.*

### Mock local (sem Cloudflare)

```bash
export SECURE_PUBLISH_MOCK=1
export SECURE_PUBLISH_COMPANY_DOMAINS=empresa.com
node packages/cli/bin/securepublish-cli.js publish examples/panel-vendas.html --title "Painel Vendas Q3"
node packages/cli/bin/securepublish-cli.js mock-serve --port 8787
```

O header `X-Mock-User: ana@empresa.com` **simula** sessão SSO. Não é login de verdade. Nunca ligue mock em produção.

E2E gravado: rode `npm run e2e:mock` e veja `E2E-MOCK.txt`.

## Setup (Cloudflare, uma vez)

### 1. Conta e token

1. [dash.cloudflare.com](https://dash.cloudflare.com) → anote o **Account ID**.
2. API token (**Account**): Workers KV Storage — Edit; Workers Scripts — Edit (deploy).  
   **Ask John/ops for the token** — never invent or commit secrets. Without it, use `SECURE_PUBLISH_MOCK=1` / `npm run e2e:mock`.

```bash
export CLOUDFLARE_API_TOKEN="…"   # from John — not in git
export CLOUDFLARE_ACCOUNT_ID="…"
export SECURE_PUBLISH_KV_NAMESPACE_ID="46d61ee3d1f7410fa081e383b776934a"
export SECURE_PUBLISH_COMPANY_DOMAINS="wises.com.br"
# Wildcard LIVE (default / demo interim tenant):
export SECURE_PUBLISH_BASE_URL="https://demo.securepublish.work"
# Or tenant slug: https://{slug}.securepublish.work
# Fallback (same Worker): https://secure-publish.clovist.workers.dev
```

| Phase | Base URL | Panel URL |
|-------|----------|-----------|
| **Wildcard** (now) | `https://demo.securepublish.work` or `https://{slug}.securepublish.work` | `https://demo.securepublish.work/{panel-id}` |
| **Fallback** | `https://secure-publish.clovist.workers.dev` | `…workers.dev/{panel-id}` |

Wildcard route `*.securepublish.work/*` → Worker **attached**. Fallback workers.dev still up. Google OAuth works. See [docs/DEPLOY-WILDCARD.md](docs/DEPLOY-WILDCARD.md) and `E2E-WILDCARD.txt`.

### 2. Instalar

```bash
npm install
node packages/cli/bin/securepublish-cli.js doctor
```

Config opcional: `.secure-publish.json` (veja `.secure-publish.json.example`).

### 3. KV

```bash
cd packages/edge
npx wrangler kv namespace create PANELS
# cole o id em wrangler.toml
```

## Ligar SSO

Cliques no dashboard Cloudflare — esta automação não faz isso por você. Preferência: **Cloudflare Access** .

### Opção A — Cloudflare Access

1. [Cloudflare Access](https://one.dash.cloudflare.com) → team name.
2. **Settings → Authentication → Login methods**: Google, GitHub e/ou Microsoft.
3. **Access → Applications → Self-hosted** no hostname do Worker.
4. Policy **Allow** + Include: **Emails ending in** `@suaempresa.com`. Isso é allowlist de **domínio**, não membership de org.
5. Copie o **AUD**. No Worker: `TEAM_DOMAIN` + `POLICY_AUD`.
6. `OAUTH_ALLOWED_DOMAINS=suaempresa.com` (mesmo domínio, checado de novo no Worker).
7. `npm run deploy`.

Até o SSO estar ligado, modo `none` responde 403 de propósito.

### Opção B — OAuth no Worker

Redirects:

- `https://<host>/_auth/callback/google`
- `https://<host>/_auth/callback/github`
- `https://<host>/_auth/callback/microsoft`

```bash
cd packages/edge
npx wrangler secret put SESSION_SECRET
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
# opcional GITHUB_* MICROSOFT_*
npx wrangler secret put OAUTH_ALLOWED_DOMAINS   # ex: empresa.com
```

Não defina `TEAM_DOMAIN`/`POLICY_AUD` se quiser modo `oauth` puro (Access tem prioridade).


## Console API (Worker)

Cameron contract: [`docs/API-CONTRACT.md`](docs/API-CONTRACT.md). Edge implementation: [`packages/edge/README.md`](packages/edge/README.md).

| Method | Path |
|--------|------|
| GET | `/api/me` |
| GET | `/api/panels?scope=mine\|company` |
| PATCH | `/api/panels/:id/access` (publisher only) |
| PUT | `/api/hosting/subdomain` · `/api/hosting/custom` |
| GET | `/auth/{google\|microsoft\|github}` |

Auth: SSO session cookie / Access JWT. CORS: exact `CONSOLE_ORIGIN` + credentials. Custom domains are claimed but **not served** until ownership is verified.

```bash
cd packages/edge && npm test && npx wrangler dev
# local: packages/edge/.dev.vars with SSO_DEV_BYPASS=1 (never production)
```

## Layout

```text
packages/cli     securepublish-cli (publish, list, revoke, doctor, mock-serve)
packages/edge    Worker (SSO + domain/--to ACL)
skills/secure-publish/SKILL.md
examples/        panel-vendas.html, panel-ops.html
docs/security-mock-checklist.md
docs/API-CONTRACT.md
docs/DEPLOY-WILDCARD.md   # *.securepublish.work LIVE (demo default)
```

## Ban list

Não usar em copy de produto: gate, gated, waitlist, early access, “SSO coming soon”, compliance, E2E, zero trust. Não afirmar membership de org no V1.

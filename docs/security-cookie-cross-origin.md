# Checklist — cookie cross-origin (Pages ↔ Worker)

Contexto V1: console em `app.securepublish.work` (Pages) chama API no Worker.
Wildcard **LIVE**: `/api/*` também responde em qualquer `*.securepublish.work` (ex. `demo.securepublish.work`) — mesmo Worker que `secure-publish.clovist.workers.dev`.
Cookie: `secure_publish_session`.

**SP_API_BASE:** não mudar o default da Cameron sem coordenar. Pode ficar em `https://secure-publish.clovist.workers.dev` **ou** apontar pra `https://demo.securepublish.work` (ou outro slug). Enquanto a API for **workers.dev**, SameSite=None. Se a API for `*.securepublish.work` (mesmo eTLD+1 que `app.`), dá pra migrar pra Lax + `Domain=.securepublish.work` (item 6).

## Obrigatório

1. **SameSite=None; Secure; HttpOnly** no Set-Cookie da sessão quando `CONSOLE_ORIGIN` está setado (já no `cookieSameSite` — None se houver origins). Sem `Secure` o browser descarta em HTTPS.
2. **CORS exact + credentials:** `Access-Control-Allow-Origin` = origin da request (só se ∈ `CONSOLE_ORIGIN`), **nunca** `*`. `Allow-Credentials: true`. Console: `fetch(..., { credentials: "include" })`.
3. **CONSOLE_ORIGIN completo:** `https://app.securepublish.work`, `https://secure-publish-app.pages.dev`, local `http://127.0.0.1:8765` se pairing. Sem trailing slash / sem wildcard `*`.
4. **`next` / return_to:** só URLs cujo origin ∈ `CONSOLE_ORIGIN` (ou remap `/app/*` → console). Bloquear open redirect.
5. **Sem `Domain=` no cookie** enquanto API estiver em `workers.dev` e console em `securepublish.work` — hosts diferentes; o cookie fica no host do Worker e o browser envia nos fetches cross-site via SameSite=None.
6. **Quando Worker for `*.securepublish.work`:** preferir API no mesmo site-eTLD+1 (`api.securepublish.work` ou path no app) e aí dá pra migrar pra **SameSite=Lax** + cookie `Domain=.securepublish.work` (melhor). Até lá, None é o correto.
7. **Terceiros / ITP:** Safari pode restringir cookies cross-site. Testar Safari + Chrome após login. Mitigação longa = same-site (item 6).
8. **Logout:** clear cookie com mesmos atributos (SameSite/Secure/Path).
9. **Não logar** valor do cookie em shots/logs; não colocar token em `localStorage` como substituto da sessão HttpOnly.

## Smoke (após deploy)

- Sem cookie: `GET /api/me` → 401; painel HTML → redirect login (não vaza body).
- Login Google → Set-Cookie com `SameSite=None; Secure; HttpOnly`.
- Do console Pages: `GET /api/me` com credentials → 200 + email.
- Origin fora da lista: CORS sem Allow-Origin / sem cookie aceito.

---
name: secure-publish
description: >-
  Publish an AI HTML dashboard with Secure Publish so only people on the
  company email domain (after sign-in) — or an explicit --to email list — can
  open it. Use when the user asks to publish, share, or host an HTML
  dashboard/panel for their company, or to restrict it to specific emails.
  V1 is email-domain access, not Workspace/Entra/GitHub Org membership.
---

# Secure Publish

There is no web “publish” button. The console only tracks URLs and views.

Install the skill (already used by the landing):

```text
npx skills add https://github.com/clovistx/secure-publish --skill "secure-publish"
```

Run the CLI from this repo (not the public npm package named `secure-publish` — that is a different project). Do **not** run `npm install secure-publish`, `npm install -g secure-publish`, or `npx secure-publish`. Use only the full form every time (npx does **not** leave `securepublish-cli` on PATH):

```bash
npx --yes github:clovistx/secure-publish <subcommand>
```

That runs this repo’s `securepublish-cli` binary for that one invocation (login, publish, help, and the rest).

User prompts this skill handles:

- PT: *Publique este dashboard HTML com Secure Publish.*
- EN: *Publish this HTML dashboard with Secure Publish.*
- PT: *Publique este HTML pra toda a empresa.*
- PT: *Publique só para clovis@wises.com.br e ana@wises.com.br.*
- EN: *Publish this HTML for the whole company.*
- EN: *Publish only to jane@acme.com.*

## What you say

Say only these lines about sign-in and publish (including the no-host branch). Do not explain the mechanism.

Check whether this machine is signed in with:

```bash
npx --yes github:clovistx/secure-publish doctor
```

Doctor prints `Status: conta ligada (email).` when linked (plus `host: …` only when a host is set), or `Status: conta não ligada nesta máquina.` when not. Exit `0` if linked, `1` if not.

If not signed in, say exactly:

> Vou abrir o login. Entra com Google na página que abrir — a conta fica ligada nesta máquina.

Then run `npx --yes github:clovistx/secure-publish login` and wait. Google only — not Microsoft, not GitHub.

When login finishes, the CLI prints `host: {value}` or an empty `host:` line. Use `{host}` lines only when that value is non-empty.

If host is non-empty, say exactly:

> Conta ligada. Publicando em {host}.

Do **not** add “aberto pra empresa”, “open to the company”, or any claim that the panel is already published company-wide on that line.

If host is empty, say exactly:

> Conta ligada. Ainda não tem endereço de publicação.

Then ask (do not invent a host):

> Onde publicar? Posso reservar {slug}.securepublish.work ou você usa um domínio próprio.

Company-wide means the same email domain as the signed-in account. If they did **not** already say who can see the panel, ask once. Ask this before you run publish:

> Quer restringir a alguém? Passe os e-mails (senão fica aberto pra empresa — mesmo domínio de e-mail).

Only the final success confirmation may state that the panel **was** published to the company (`Publicado pra **toda a empresa**`). The restrict question may mention the default (open to the company, same email domain) as the alternative to restricting. Do not claim on the post-login line that the panel is already open company-wide.

Only after they answer (or they already specified access) publish:

```bash
# company-wide (same email domain; no --to)
npx --yes github:clovistx/secure-publish publish ./dashboard.html --title "Painel"
# restricted to specific emails
npx --yes github:clovistx/secure-publish publish ./dashboard.html --to clovis@wises.com.br,ana@wises.com.br
```

On success, say exactly (do not invent `{url}` — only the url the command printed):

> Publicado pra **toda a empresa**: {url}

If they passed emails:

> Publicado só para {emails}: {url}

On failure, match what the CLI reported — do **not** always say “Tenta de novo em instantes”:

| CLI reports | Say exactly |
|-------------|-------------|
| `File not found: …` or `HTML file is empty` | Arquivo HTML não encontrado ou vazio. Confira o caminho e tente de novo. |
| `Inclua pelo menos um e-mail em --to …` | Inclua pelo menos um e-mail válido em --to. |
| `Conta não ligada nesta máquina. …` | Conta não ligada nesta máquina. Vou abrir o login de novo. |
| `Não consegui publicar agora…` (network/server) | Não consegui publicar agora.{optional host} Tenta de novo em instantes. |

For the not-logged-in / session-expired line, go back to login (`npx --yes github:clovistx/secure-publish login`). For the network/server line, if host is non-empty insert ` A conta está ligada em {host}.` before “Tenta de novo…”; if host is empty, omit that sentence. Only the network/server line may say “Tenta de novo em instantes”. Never ask them for an infrastructure secret.

## Access (V1)

| UI label | Command | What it actually checks |
|----------|---------|-------------------------|
| Toda a empresa / Whole company | default (no `--to`) | Email **domain** after sign-in. Example: `@wises.com.br`. |
| Só estas pessoas / Only these people | `--to a@x,b@y` | Explicit email list. Still requires sign-in. |

- Same domain as the account is the default when `--to` is omitted.
- This is **not** Google Workspace, Microsoft Entra, or GitHub Org membership.
- A personal account on the same domain can pass a domain-only policy. Say so if asked.
- `--to` stays the flag name.

## Errors (user-facing)

| Situation | PT | EN |
|-----------|----|----|
| Email not on company domain | Seu e-mail não é do domínio desta empresa. Peça acesso ou use a conta corporativa. | Your email isn’t on this company’s domain. Ask for access or use your work account. |
| Signed in, no permission | Você está logado, mas não tem permissão neste dashboard. | You’re signed in, but you don’t have access to this dashboard. |
| Missing emails when they asked for a list | Inclua pelo menos um e-mail | Add at least one email |

## Do not claim

1. Never claim that a “Continuar como …” screen on the landing/demo authenticates anyone — it only proves the *flow*.
2. Do not imitate the Google window. No logos or brand colors on a fake sign-in.
3. The panel URL is not a credential. Without sign-in, the page does not return the HTML.
4. A domain list is not org membership.
5. Do not claim E2E encryption, compliance/SOC2, “nobody ever leaks”, or a waitlist that already saved the email.

Do not use: gate, gated, waitlist, early access, “SSO coming soon”, compliance, E2E, zero trust, “org member”, “Workspace membership”.

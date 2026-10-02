# Secure Publish — copy alpha (console + agent)
**Status:** strings fechadas pra Cameron colar  
**Regras:** agent-first · sem waitlist · **V1 Lock A:** viewer = mesmo domínio de e-mail após SSO (não membership Workspace/Entra/GitHub Org) · allowlist aperta depois · sem “gate”

**Changelog:** trust.org / signup.note / erros / share.help alinhados ao edge de domínio (Marcus/John). Membership = fase seguinte.

---

## 1. Console — nav / listas

| Key | PT | EN |
|-----|----|----|
| nav.my | Meus links | My links |
| nav.company | Da empresa | Company-wide |
| nav.hosting | Hosting | Hosting |
| empty.my.title | Você ainda não publicou nada | You haven’t published anything yet |
| empty.my.body | Publique pelo agente ou pela CLI. Aqui você só acompanha URLs e acessos. | Publish with your agent or the CLI. This console tracks URLs and views. |
| empty.company.title | Nenhum link aberto pra empresa | No company-wide links yet |
| empty.company.body | Quando alguém publicar pra toda a org, aparece aqui. | When someone publishes for the whole org, it shows up here. |
| col.url | URL | URL |
| col.publishedAt | Publicado em | Published |
| col.views | Acessos | Views |
| col.access | Quem pode ver | Who can view |
| access.org | Toda a empresa | Whole company |
| access.allowlist | Só pessoas convidadas | Invited people only |
| row.menu | Mais opções | More options |
| row.share | Compartilhar | Share |
| row.copyUrl | Copiar URL | Copy URL |
| row.open | Abrir | Open |
| analytics.viewers | Quem acessou | Who viewed |
| analytics.first | Primeiro acesso | First seen |
| analytics.last | Último acesso | Last seen |
| analytics.empty | Ninguém abriu ainda | No views yet |

---

## 2. Console — Share (⋯)

| Key | PT | EN |
|-----|----|----|
| share.title | Compartilhar | Share |
| share.modeOrg | Toda a empresa | Whole company |
| share.modeOrg.help | Quem tem o mesmo domínio de e-mail da empresa, após login (Google / Microsoft / GitHub). | Anyone with your company email domain, after sign-in (Google / Microsoft / GitHub). |
| share.modeAllowlist | Só estas pessoas | Only these people |
| share.modeAllowlist.help | Ainda exige login. Só estes e-mails (do domínio da empresa) abrem o link. | Still requires sign-in. Only these emails (on the company domain) can open the link. |
| share.emails | E-mails | Emails |
| share.emails.placeholder | nome@empresa.com, outro@empresa.com | name@company.com, other@company.com |
| share.invite | Enviar convite por e-mail | Send email invite |
| share.save | Salvar | Save |
| share.cancel | Cancelar | Cancel |
| share.error.minEmail | Inclua pelo menos um e-mail | Add at least one email |

---

## 3. Console — Hosting / onboarding

| Key | PT | EN |
|-----|----|----|
| hosting.title | Onde seus dashboards vão viver | Where your dashboards will live |
| hosting.subdomain | Subdomínio Secure Publish | Secure Publish subdomain |
| hosting.subdomain.help | Ex.: wise.securepublish.work | e.g. wise.securepublish.work |
| hosting.subdomain.placeholder | sua-empresa | your-company |
| hosting.custom | Domínio próprio | Custom domain |
| hosting.custom.help | Ex.: dashboards.wises.com.br (CNAME pro nosso edge) | e.g. dashboards.acme.com (CNAME to our edge) |
| hosting.save | Continuar | Continue |
| hosting.conflict | Esse subdomínio já está em uso | That subdomain is taken |

---

## 4. Console — Signup (fallback web)

| Key | PT | EN |
|-----|----|----|
| signup.title | Criar conta e começar | Create account — start now |
| signup.lede | Entre com Google, Microsoft ou GitHub. O login da empresa (mesmo domínio de e-mail) protege seus dashboards. | Sign in with Google, Microsoft, or GitHub. Company sign-in (same email domain) protects your dashboards. |
| signup.google | Continuar com Google | Continue with Google |
| signup.microsoft | Continuar com Microsoft | Continue with Microsoft |
| signup.github | Continuar com GitHub | Continue with GitHub |
| signup.note | V1: quem vê precisa do mesmo domínio de e-mail da conta (ex. @wises.com.br). Membership de org (Workspace/Entra/GitHub Org) vem depois. | V1: viewers need the same email domain as the account (e.g. @acme.com). Full org membership (Workspace/Entra/GitHub Org) comes later. |
| signup.preferAgent | Prefere pelo agente? Instale a skill e ela abre o cadastro pra você. | Prefer the agent? Install the skill — it opens signup for you. |

---

## 5. Landing CTA (substitui waitlist) — pra aplicar com a landing amanhã / alpha

| Key | PT | EN |
|-----|----|----|
| cta.primary | Criar conta e começar | Create account — start now |
| cta.sub | Login com Google, Microsoft ou GitHub. Quem vê precisa do mesmo domínio de e-mail. | Sign in with Google, Microsoft, or GitHub. Viewers need the same email domain. |
| path.happy | Instale a skill, entre com a conta da empresa e publique pelo agente. O console mostra URLs, quem abriu e quando. | Install the skill, sign in with your company account, and publish from the agent. The console shows URLs, who opened them, and when. |
| trust.org | Só e-mails do domínio da empresa abrem o link (após SSO). | Only emails on your company domain can open the link (after SSO). |
| trust.idp | Login com Google, Microsoft ou GitHub. Okta / SAML em seguida. | Sign in with Google, Microsoft, or GitHub. Okta / SAML coming next. |
| trust.demo | A demo da landing simula o fluxo; o login de verdade roda no produto. | The landing demo simulates the flow; real sign-in runs in the product. |

---

## 6. Agent / skill — prompts e mensagens

### 6.1 Install (já na landing; manter)

```text
npx skills add https://github.com/clovistx/secure-publish --skill "secure-publish"
```

Depois diga ao agente:  
**PT:** Publique este dashboard HTML com Secure Publish.  
**EN:** Publish this HTML dashboard with Secure Publish.

### 6.2 Skill strings (UX do agente)

| Situação | PT | EN |
|----------|----|----|
| sem conta | Você ainda não tem conta Secure Publish. Vou abrir o cadastro — entre com Google, Microsoft ou GitHub (e-mail da empresa). | You don’t have a Secure Publish account yet. I’ll open signup — use Google, Microsoft, or GitHub (company email). |
| aguardando link | Depois de criar a conta, volto aqui. Código de vínculo: {code} | After you create the account, I’ll continue here. Link code: {code} |
| conta ok | Conta vinculada. | Account linked. |
| sem hosting | Onde publicar? Posso reservar {slug}.securepublish.work ou você usa um domínio próprio. | Where should we host? I can reserve {slug}.securepublish.work or you can use a custom domain. |
| publish org | Publicado pra **toda a empresa**: {url} | Published for the **whole company**: {url} |
| publish allowlist | Publicado só para {emails}: {url} | Published only for {emails}: {url} |
| pedir --to | Quer restringir a alguém? Passe os e-mails (senão fica aberto pra org). | Want to restrict access? Pass emails (otherwise it’s open to the org). |
| erro sem domínio | Seu e-mail não é do domínio desta empresa. Peça acesso ou use a conta corporativa. | Your email isn’t on this company’s domain. Ask for access or use your work account. |
| erro 403 viewer | Você está logado, mas não tem permissão neste dashboard. | You’re signed in, but you don’t have access to this dashboard. |

### 6.3 Exemplos de fala do usuário → agente

- PT: *Publique este HTML pra toda a empresa.*  
- PT: *Publique só para clovis@wises.com.br e ana@wises.com.br.*  
- EN: *Publish this HTML for the whole company.*  
- EN: *Publish only to jane@acme.com.*

---

## 7. E-mail de convite (allowlist) — assunto + corpo curto

**PT assunto:** Você recebeu um dashboard Secure Publish  
**PT corpo:** {publisher} compartilhou um dashboard com você. Abra {url} e entre com a conta da empresa ({email}).  

**EN subject:** You’ve been shared a Secure Publish dashboard  
**EN body:** {publisher} shared a dashboard with you. Open {url} and sign in with your company account ({email}).

---

## 8. Ban list (copy)

Não usar: gate, gated, waitlist, early access, “SSO coming soon”, “copie e rode agora” (install ainda exemplo até skill real), compliance, E2E, zero trust.

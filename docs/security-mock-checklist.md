# Security checklist — mock auth / demo flow

Para README e skill Secure Publish. Mock ≠ produto.

## Bullets (copiar)

1. **Mock ≠ SSO.** A tela “Continuar como …” na landing/demo prova o *fluxo*; não autentica ninguém. Nunca diga “login Google/Microsoft/GitHub de verdade” nessa página.
2. **Não imite UI do IdP.** Sem logos, cores ou “janelinha Google”. Use “Continuar como …” genérico + rótulo visível: *Demo do fluxo · não é login [IdP] de verdade*.
3. **URL do painel não é credencial.** `/{panel-id}` só identifica o HTML no KV. Sem sessão SSO (Access JWT ou cookie OAuth), o Worker responde 403 — mesmo com a URL.
4. **Allowlist ≠ org membership.** `OAUTH_ALLOWED_DOMAINS` (e-mail `@empresa.com`) ou política Access “emails ending in” é **allowlist de domínio**. Isso **não** verifica membership em org Google Workspace / Entra / GitHub Org. Conta pessoal no mesmo domínio (ou IdP sem restrição) pode passar se a política for só “authenticated”.
5. **Não claimar:** E2E encryption, compliance/SOC2, “ninguém nunca vaza”, “compatível com IdP X” antes do OAuth/Access desse IdP estar ligado, waitlist que “já salvou o e-mail” sem storage real, `SSO_DEV_BYPASS` / auth mock em produção.

## Allowlist vs org (resumo)

| Controle | O que faz | Limite |
|----------|-----------|--------|
| Só “authenticated” no IdP | Qualquer conta que logar no Google/MS/GitHub | Largo demais pra B2B |
| Allowlist de domínio (`OAUTH_ALLOWED_DOMAINS` / Access email domain) | Só e-mails `@suaempresa.com` | Bom MVP; não prova que a conta é da org (aliases, freelancers no domínio, etc.) |
| Org / group membership (futuro) | Google Workspace group, Entra group, GitHub org/team | Conta enterprise de verdade |

**Default recomendado V1:** domínio allowlist + IdPs Google/Microsoft/GitHub. Org membership = fase seguinte (Okta/SAML ou groups API).

## Onde aplicar

- Landing: disclaimer na demo; trust sem badges de IdP “já vivo” sem OAuth.
- Skill/README: estes 5 bullets; CLI name `panel-gate` ok em docs avançados.
- Produção: nunca `dev-bypass`; secrets só no Worker; falha fechada se SSO não configurado.

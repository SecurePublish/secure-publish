/**
 * Bilingual (PT then EN) product HTML for panel/tenant hosts.
 * Same chrome as the unauthenticated "Entrar para ver" login page.
 * Never interpolates host, path, panel id, ACL data, or domain lists.
 */

const SWITCH_HREF = "https://app.securepublish.work/auth/switch";

export const VIEWER_COPY = {
  root: {
    pt: "Este endereço só abre dashboards pelo link completo. Peça o link a quem publicou.",
    en: "This address only opens dashboards from the full link. Ask whoever published it for the link.",
  },
  notFound: {
    pt: "Não achamos este dashboard. O link pode estar errado ou ter sido removido. Peça um link novo a quem publicou.",
    en: "We couldn't find this dashboard. The link may be wrong or it was removed. Ask whoever published it for a new link.",
  },
  generic403: {
    pt: "Você entrou, mas este dashboard não foi liberado pra sua conta. Entre com outra conta ou peça acesso a quem publicou.",
    en: "You're signed in, but this dashboard isn't shared with your account. Sign in with another account or ask whoever published it for access.",
  },
  domainNotAllowed: {
    pt: "Este dashboard só abre pra quem entra com o e-mail da empresa. Entre com a conta da empresa ou peça acesso a quem publicou.",
    en: "This dashboard only opens for people who sign in with the company email. Sign in with your company account or ask whoever published it for access.",
  },
  switchPt: "Entrar com outra conta",
  switchEn: "Sign in with another account",
};

export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function titleFromPt(pt) {
  const first = String(pt || "").split(". ")[0] || "Secure Publish";
  return `${first} — Secure Publish`;
}

const PAGE_CSS = `:root{
  --cream:#FAF8F5;--cream-2:#F3EFE9;--stone:#E8E2D9;--ink:#292524;--ink-soft:#57534E;--muted:#78716C;
  --line:#E7E0D6;--sage:#5F7A61;--sage-hover:#4E6650;--sage-soft:#E8F0E9;--white:#FFFEFC;
  --display:"Fraunces",Georgia,serif;--sans:"DM Sans",system-ui,sans-serif;
  --radius:14px;--radius-sm:10px;
  --shadow:0 1px 2px rgba(41,37,36,.04),0 8px 24px rgba(41,37,36,.05);
  --max:540px;
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;
  font-family:var(--sans);font-size:1rem;line-height:1.5;color:var(--ink);
  background:
    radial-gradient(1200px 600px at 10% -10%,rgba(95,122,97,.08),transparent 55%),
    var(--cream-2);
}
.topbar{
  display:flex;align-items:center;justify-content:space-between;gap:1rem;
  padding:.85rem 1.35rem;border-bottom:1px solid var(--line);
  background:rgba(255,254,252,.94);backdrop-filter:blur(10px);
  position:sticky;top:0;z-index:20;
}
.topbar__brand{
  font-family:var(--display);font-weight:600;font-size:1.12rem;letter-spacing:-.02em;
  color:var(--ink);text-decoration:none;display:inline-flex;align-items:center;gap:.45rem;
}
.topbar__mark{display:inline-flex;width:1.35rem;height:1.35rem;color:var(--sage);flex-shrink:0}
.topbar__mark svg{width:100%;height:100%;display:block}
.main{width:min(100% - 2rem,var(--max));margin:2.25rem auto 3rem}
.page-head{margin-bottom:1.35rem}
.page-head h1{
  margin:0 0 .4rem;font-family:var(--display);font-weight:600;font-size:clamp(1.55rem,3vw,1.85rem);
  letter-spacing:-.02em;line-height:1.2;color:var(--ink);
}
.lede{margin:0;color:var(--ink-soft);font-size:1.02rem;line-height:1.55}
.card{
  background:var(--white);border:1px solid var(--stone);border-radius:var(--radius);
  padding:1.35rem 1.35rem 1.4rem;box-shadow:var(--shadow);
}
.card p{margin:0 0 .85rem}
.card p:last-child{margin-bottom:0}
.en{color:var(--ink-soft)}
.idp-btn{
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.2rem;
  width:100%;margin-top:1rem;padding:.95rem 1.15rem;border:1px solid var(--stone);border-radius:var(--radius-sm);
  background:var(--cream);font:inherit;font-weight:600;font-size:.98rem;color:var(--ink);
  text-decoration:none;transition:border-color .15s,background .15s,box-shadow .15s;
}
.idp-btn__en{font-weight:500;font-size:.84rem;color:var(--muted);line-height:1.2}
.idp-btn:hover{
  border-color:var(--sage);background:var(--sage-soft);box-shadow:var(--shadow);
  color:var(--ink);text-decoration:none;
}`;

/**
 * @param {{
 *   status: number,
 *   pt: string,
 *   en: string,
 *   email?: string,
 *   switchAccount?: boolean,
 * }} opts
 */
export function viewerPage({ status, pt, en, email, switchAccount = false }) {
  const title = titleFromPt(pt);
  const heading = String(pt || "").split(". ")[0];
  let sessionBlock = "";
  if (email) {
    const safe = escapeHtml(email);
    sessionBlock = `<p lang="pt-BR">Você entrou como ${safe}.</p>
    <p class="en" lang="en">Signed in as ${safe}.</p>`;
  }
  let switchBlock = "";
  if (switchAccount) {
    switchBlock = `<a class="idp-btn" id="sp-switch-account" href="${SWITCH_HREF}">
      <span>${VIEWER_COPY.switchPt}</span>
      <span class="idp-btn__en" lang="en">${VIEWER_COPY.switchEn}</span>
    </a>
    <script>
    (function(){
      var a=document.getElementById("sp-switch-account");
      if(!a)return;
      a.href=${JSON.stringify(SWITCH_HREF + "?return=")}+encodeURIComponent(location.href);
    })();
    </script>`;
  }

  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=Fraunces:opsz,wght@9..144,550;9..144,600&display=swap" rel="stylesheet"/>
<style>
${PAGE_CSS}
</style>
</head>
<body>
<header class="topbar">
  <span class="topbar__brand">
    <span class="topbar__mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none"><rect x="3" y="11" width="18" height="10" rx="2" stroke="currentColor" stroke-width="1.75"/><path d="M7 11V8a5 5 0 0 1 10 0v3" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/><circle cx="12" cy="16" r="1.5" fill="currentColor"/></svg>
    </span>
    Secure Publish
  </span>
</header>
<main class="main">
  <div class="page-head">
    <h1>${heading}</h1>
  </div>
  <div class="card">
    <p lang="pt-BR">${pt}</p>
    <p class="lede en" lang="en">${en}</p>
    ${sessionBlock}
    ${switchBlock}
  </div>
</main>
</body>
</html>`;

  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

export function notFoundViewerPage() {
  return viewerPage({
    status: 404,
    pt: VIEWER_COPY.notFound.pt,
    en: VIEWER_COPY.notFound.en,
  });
}

export function rootViewerPage() {
  return viewerPage({
    status: 404,
    pt: VIEWER_COPY.root.pt,
    en: VIEWER_COPY.root.en,
  });
}

export function generic403ViewerPage(email) {
  return viewerPage({
    status: 403,
    pt: VIEWER_COPY.generic403.pt,
    en: VIEWER_COPY.generic403.en,
    email,
    switchAccount: true,
  });
}

export function domainNotAllowedViewerPage(email) {
  return viewerPage({
    status: 403,
    pt: VIEWER_COPY.domainNotAllowed.pt,
    en: VIEWER_COPY.domainNotAllowed.en,
    email,
    switchAccount: true,
  });
}

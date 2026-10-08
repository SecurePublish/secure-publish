/**
 * Browser-facing panel/tenant HTML (not /api/* or /auth/* JSON).
 * Recipients opening a link see bilingual PT+EN product copy — never intern strings.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { mintSessionCookie } from "../src/sso.js";

const PANEL_ID = "aaaaaaaaaaaaaaaaaaaaaaaa";
const UNKNOWN_ID = "ffffffffffffffffffffffff";
const PANEL_HTML = "<html>viewer-pages-ok</html>";
const EMAIL = "ana@wises.com.br";
const OTHER_EMAIL = "bob@acme.example";
const GMAIL_VIEWER = "bob@gmail.com";
const GMAIL_PUBLISHER = "ana@gmail.com";
const GMAIL_COMPANY_ID = "222222222222222222222222";

const COPY = {
  rootPt: "Este endereço só abre dashboards pelo link completo. Peça o link a quem publicou.",
  rootEn: "This address only opens dashboards from the full link. Ask whoever published it for the link.",
  notFoundPt:
    "Não achamos este dashboard. O link pode estar errado ou ter sido removido. Peça um link novo a quem publicou.",
  notFoundEn:
    "We couldn't find this dashboard. The link may be wrong or it was removed. Ask whoever published it for a new link.",
  generic403Pt:
    "Você entrou, mas este dashboard não foi liberado pra sua conta. Entre com outra conta ou peça acesso a quem publicou.",
  generic403En:
    "You're signed in, but this dashboard isn't shared with your account. Sign in with another account or ask whoever published it for access.",
  domainPt:
    "Este dashboard só abre pra quem entra com o e-mail da empresa. Entre com a conta da empresa ou peça acesso a quem publicou.",
  domainEn:
    "This dashboard only opens for people who sign in with the company email. Sign in with your company account or ask whoever published it for access.",
  signedInPt: (email) => `Você entrou como ${email}.`,
  signedInEn: (email) => `Signed in as ${email}.`,
  switchPt: "Entrar com outra conta",
  switchEn: "Sign in with another account",
};

const OLD_DEV = ["SSO/ACL", "Console API", "invalid or unknown panel id", "host not bound"];

function memoryKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
    async delete(key) {
      store.delete(key);
    },
    async list({ prefix = "", limit = 1000 } = {}) {
      const keys = [...store.keys()]
        .filter((k) => k.startsWith(prefix))
        .sort()
        .map((name) => ({ name }));
      return { keys: keys.slice(0, limit), list_complete: true, cursor: undefined };
    },
    _store: store,
  };
}

function oauthEnv(panels, extra = {}) {
  return {
    PANELS: panels,
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
    ...extra,
  };
}

async function sessionCookie(env, email) {
  const setCookie = await mintSessionCookie(
    {
      email,
      provider: "google",
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    env.SESSION_SECRET,
    env,
    "https://app.securepublish.work/_auth/callback/google"
  );
  return setCookie.split(";")[0];
}

function panelRecord(overrides = {}) {
  return {
    v: 1,
    title: "Ops",
    publishedAt: "2026-10-08T00:00:00Z",
    publisherEmail: EMAIL,
    access: { mode: "company", domains: ["wises.com.br"] },
    html: PANEL_HTML,
    ...overrides,
  };
}

function req(url, host, extraHeaders = {}) {
  return new Request(url, {
    headers: { Host: host, ...extraHeaders },
    redirect: "manual",
  });
}

function assertHtmlPage(res, body) {
  assert.match(res.headers.get("content-type") || "", /^text\/html;\s*charset=utf-8$/i);
  assert.match(res.headers.get("cache-control") || "", /no-store/i);
  assert.match(body, /<html lang=/i);
  assert.match(body, /<title>/i);
  assert.doesNotMatch(body, /<script\s+src=/i);
  for (const s of OLD_DEV) {
    assert.equal(body.includes(s), false, `old dev string present: ${s}`);
  }
}

function assertBilingual(body, pt, en) {
  const ptAt = body.indexOf(pt);
  const enAt = body.indexOf(en);
  assert.notEqual(ptAt, -1, `missing PT: ${pt}`);
  assert.notEqual(enAt, -1, `missing EN: ${en}`);
  assert.ok(ptAt < enAt, "PT must appear before EN");
}

describe("viewer HTML — host root", () => {
  it("GET / on a panel host is 404 HTML with host-root copy, not intern text", async () => {
    const env = oauthEnv(memoryKv({ "host:sub:wise": EMAIL }));
    const res = await worker.fetch(req("https://wise.securepublish.work/", "wise.securepublish.work"), env);
    assert.equal(res.status, 404);
    const body = await res.text();
    assertHtmlPage(res, body);
    assertBilingual(body, COPY.rootPt, COPY.rootEn);
    assert.equal(body.includes(COPY.notFoundPt), false);
  });
});

describe("viewer HTML — unknown panel id / host not bound", () => {
  it("unknown panel id is 404 HTML with not-found copy", async () => {
    const env = oauthEnv(
      memoryKv({
        "host:sub:wise": EMAIL,
      })
    );
    const res = await worker.fetch(
      req(`https://wise.securepublish.work/${UNKNOWN_ID}`, "wise.securepublish.work"),
      env
    );
    assert.equal(res.status, 404);
    const body = await res.text();
    assertHtmlPage(res, body);
    assertBilingual(body, COPY.notFoundPt, COPY.notFoundEn);
    assert.equal(body.includes(UNKNOWN_ID), false, "must not echo panel id");
    assert.equal(body.includes("wise.securepublish.work"), false, "must not echo host");
  });

  it("unbound host (existing id, no lock) body is byte-identical to unknown id", async () => {
    const env = oauthEnv(
      memoryKv({
        [PANEL_ID]: JSON.stringify(panelRecord()),
      })
    );
    const unknown = await worker.fetch(
      req(`https://wise.securepublish.work/${UNKNOWN_ID}`, "wise.securepublish.work"),
      env
    );
    const unbound = await worker.fetch(
      req(`https://zombie.securepublish.work/${PANEL_ID}`, "zombie.securepublish.work"),
      env
    );
    assert.equal(unknown.status, 404);
    assert.equal(unbound.status, 404);
    const a = await unknown.text();
    const b = await unbound.text();
    assert.equal(a, b);
    assertHtmlPage(unbound, b);
    assertBilingual(b, COPY.notFoundPt, COPY.notFoundEn);
    assert.equal(b.includes(PANEL_ID), false);
    assert.equal(b.includes("zombie.securepublish.work"), false);
  });

  it("unowned reserved infra host (api.) 404 is the same not-found HTML", async () => {
    const env = oauthEnv(
      memoryKv({
        [PANEL_ID]: JSON.stringify(panelRecord()),
      })
    );
    const api = await worker.fetch(
      req(`https://api.securepublish.work/${PANEL_ID}`, "api.securepublish.work"),
      env
    );
    const unknown = await worker.fetch(
      req(`https://wise.securepublish.work/${UNKNOWN_ID}`, "wise.securepublish.work"),
      env
    );
    assert.equal(api.status, 404);
    const apiBody = await api.text();
    const unknownBody = await unknown.text();
    assert.equal(apiBody, unknownBody);
    assert.equal(apiBody.includes(PANEL_HTML), false);
    assert.equal(api.headers.get("location"), null);
  });
});

describe("viewer HTML — panel 403", () => {
  it("generic 403 (allowlist miss) shows new copy, session email, switch button; no ACL internals", async () => {
    const env = oauthEnv(
      memoryKv({
        [PANEL_ID]: JSON.stringify(
          panelRecord({
            access: { mode: "allowlist", emails: [EMAIL] },
          })
        ),
        "host:sub:wise": EMAIL,
      })
    );
    const cookie = await sessionCookie(env, OTHER_EMAIL);
    const res = await worker.fetch(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work", {
        Cookie: cookie,
      }),
      env
    );
    assert.equal(res.status, 403);
    const body = await res.text();
    assertHtmlPage(res, body);
    assertBilingual(body, COPY.generic403Pt, COPY.generic403En);
    assertBilingual(body, COPY.signedInPt(OTHER_EMAIL), COPY.signedInEn(OTHER_EMAIL));
    assert.ok(body.includes(COPY.switchPt));
    assert.ok(body.includes(COPY.switchEn));
    assert.match(body, /https:\/\/app\.securepublish\.work\/auth\/switch/);
    assert.match(body, /location\.href/);
    assert.equal(body.includes(COPY.domainPt), false);
    assert.equal(body.includes("not_on_allowlist"), false);
    assert.equal(body.includes(EMAIL), false, "must not show publisher / allowlist emails");
    assert.equal(body.includes("public_company_domain"), false);
    assert.equal(body.includes("domain_not_allowed"), false);
    assert.equal(body.includes("wise.securepublish.work"), false);
    assert.equal(body.includes(PANEL_ID), false);
    assert.equal(res.headers.get("x-secure-publish-acl"), null);
  });

  it("public-domain old company panel uses the SAME generic 403 page as allowlist miss", async () => {
    const env = oauthEnv(
      memoryKv({
        [GMAIL_COMPANY_ID]: JSON.stringify({
          v: 1,
          title: "Old",
          publishedAt: "2026-10-01T00:00:00Z",
          publisherEmail: GMAIL_PUBLISHER,
          access: { mode: "company", domains: ["gmail.com"] },
          html: PANEL_HTML,
        }),
      })
    );
    const viewer = await worker.fetch(
      new Request(`https://edge.workers.dev/${GMAIL_COMPANY_ID}`, {
        headers: {
          Host: "edge.workers.dev",
          Cookie: await sessionCookie(env, GMAIL_VIEWER),
        },
        redirect: "manual",
      }),
      env
    );
    const allowEnv = oauthEnv(
      memoryKv({
        [PANEL_ID]: JSON.stringify(
          panelRecord({
            access: { mode: "allowlist", emails: [EMAIL] },
          })
        ),
        "host:sub:wise": EMAIL,
      })
    );
    const allowMiss = await worker.fetch(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work", {
        Cookie: await sessionCookie(allowEnv, GMAIL_VIEWER),
      }),
      allowEnv
    );
    assert.equal(viewer.status, 403);
    assert.equal(allowMiss.status, 403);
    const a = await viewer.text();
    const b = await allowMiss.text();
    assert.equal(a, b);
    assertBilingual(a, COPY.generic403Pt, COPY.generic403En);
    assert.ok(a.includes(COPY.signedInPt(GMAIL_VIEWER)));
    assert.equal(a.includes("public_company_domain"), false);
    assert.equal(a.includes(GMAIL_PUBLISHER), false);
    assert.equal(a.includes("gmail.com") && !a.includes(GMAIL_VIEWER), false);
  });

  it("domain_not_allowed 403 uses its own copy plus session email and switch button", async () => {
    const env = oauthEnv(
      memoryKv({
        [PANEL_ID]: JSON.stringify(panelRecord()),
        "host:sub:wise": EMAIL,
      })
    );
    const res = await worker.fetch(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work", {
        Cookie: await sessionCookie(env, OTHER_EMAIL),
      }),
      env
    );
    assert.equal(res.status, 403);
    const body = await res.text();
    assertHtmlPage(res, body);
    assertBilingual(body, COPY.domainPt, COPY.domainEn);
    assertBilingual(body, COPY.signedInPt(OTHER_EMAIL), COPY.signedInEn(OTHER_EMAIL));
    assert.ok(body.includes(COPY.switchPt));
    assert.ok(body.includes(COPY.switchEn));
    assert.equal(body.includes(COPY.generic403Pt), false);
    assert.equal(body.includes("domain_not_allowed"), false);
    assert.equal(body.includes("wises.com.br"), false, "must not echo company domain");
    assert.equal(body.includes("OAUTH_ALLOWED_DOMAINS"), false);
    assert.equal(body.includes(EMAIL), false);
    assert.equal(body.includes(PANEL_ID), false);
    assert.equal(res.headers.get("x-secure-publish-acl"), null);
  });

  it("escapes a hostile session email in the 403 page", async () => {
    const evil = `x@wises.com.br"><script>alert(1)</script>`;
    const env = oauthEnv(
      memoryKv({
        [PANEL_ID]: JSON.stringify(
          panelRecord({
            access: { mode: "allowlist", emails: [EMAIL] },
          })
        ),
        "host:sub:wise": EMAIL,
      })
    );
    const res = await worker.fetch(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work", {
        Cookie: await sessionCookie(env, evil),
      }),
      env
    );
    assert.equal(res.status, 403);
    const body = await res.text();
    assert.equal(body.includes("<script>alert(1)</script>"), false);
    assert.ok(body.includes("&lt;script&gt;") || body.includes("&#"));
  });
});

describe("viewer HTML — /api/* JSON unchanged", () => {
  it("GET /api/me without session still returns JSON unauthorized", async () => {
    const env = oauthEnv(memoryKv());
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/me", {
        headers: { Origin: "https://app.securepublish.work" },
      }),
      env
    );
    assert.equal(res.status, 401);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    assert.deepEqual(await res.json(), { error: "unauthorized" });
  });

  it("GET /api/me with disallowed OAuth domain still returns JSON domain_not_allowed", async () => {
    const env = oauthEnv(memoryKv(), { OAUTH_ALLOWED_DOMAINS: "wises.com.br" });
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/me", {
        headers: {
          Origin: "https://app.securepublish.work",
          Cookie: await sessionCookie(env, OTHER_EMAIL),
        },
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    assert.deepEqual(await res.json(), { error: "domain_not_allowed" });
  });
});

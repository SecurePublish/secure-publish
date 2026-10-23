/**
 * User-facing CLI copy. Product rewords these strings; keep the keys stable.
 * Commands that the user should run sit alone on the following line (no punctuation).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function readPinnedCliVersion() {
  const pkgPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  const version = String(JSON.parse(fs.readFileSync(pkgPath, "utf8")).version || "").trim();
  if (!version || version === "latest" || !/^\d+\.\d+\.\d+/.test(version)) {
    throw new Error("CLI package.json version must be a pinned semver");
  }
  return version;
}

export const CLI_VERSION = readPinnedCliVersion();
/** Always pinned. Never bare `npx @securepublish/cli` and never `@latest`. */
export const NPX_CLI = `npx --yes @securepublish/cli@${CLI_VERSION}`;

function runLines(intro, command, afterIntro, afterCommand) {
  let out = `${intro}\n${command}`;
  if (afterIntro) out += `\n${afterIntro}\n${afterCommand}`;
  return out;
}

export const MESSAGES = {
  errorPrefix: {
    pt: "Erro:",
    en: "Error:",
  },
  sessionExpired: {
    pt: runLines(
      "Sua sessão expirou ou foi encerrada. Para entrar de novo, rode:",
      `${NPX_CLI} login`
    ),
    en: runLines(
      "Your session expired or was ended. To sign in again, run:",
      `${NPX_CLI} login`
    ),
  },
  notLoggedIn: {
    pt: runLines("Você ainda não entrou nesta máquina. Para entrar, rode:", `${NPX_CLI} login`),
    en: runLines("You're not signed in on this machine yet. To sign in, run:", `${NPX_CLI} login`),
  },
  loginFailed: {
    pt: "Não consegui fazer o login agora. Tente de novo em instantes.",
    en: "Couldn't connect the account right now. Try again in a moment.",
  },
  loginExpired: {
    pt: runLines("O pedido de login expirou. Para começar de novo, rode:", `${NPX_CLI} login`),
    en: runLines("The sign-in request expired. To start again, run:", `${NPX_CLI} login`),
  },
  loginDenied: {
    pt: runLines("O login foi recusado no navegador. Para tentar de novo, rode:", `${NPX_CLI} login`),
    en: runLines("Sign-in was denied in the browser. To try again, run:", `${NPX_CLI} login`),
  },
  loginNoPending: {
    pt: runLines(
      "Não tem nenhum login em andamento. Primeiro rode:",
      `${NPX_CLI} login`,
      "Quando aprovar no navegador, rode:",
      `${NPX_CLI} login --finish`
    ),
    en: runLines(
      "There's no sign-in in progress. First run:",
      `${NPX_CLI} login`,
      "Once you approve it in the browser, run:",
      `${NPX_CLI} login --finish`
    ),
  },
  logoutKeepLocal: {
    pt: "Não consegui sair da conta agora. Esta máquina continua conectada. Tente de novo em instantes.",
    en: "Couldn't sign out right now. This machine is still signed in. Try again in a moment.",
  },
  logoutDone: {
    pt: "Você saiu da conta nesta máquina.",
    en: "You're signed out on this machine.",
  },
  noHostLogin: {
    pt: "Login feito. Falta só um passo, que você faz uma vez só: escolher o endereço da sua empresa, como suaempresa.securepublish.work. Escolha em https://app.securepublish.work/app/hosting.html e depois volte aqui pra publicar.",
    en: "You're signed in. One step left, and you only do it once: choose your company's address, like yourcompany.securepublish.work. Choose it at https://app.securepublish.work/app/hosting.html, then come back here to publish.",
  },
  noHostPublish: {
    pt: "Ainda não publiquei: sua empresa não tem um endereço no Secure Publish. Escolha um em https://app.securepublish.work/app/hosting.html e tente publicar de novo. Isso só precisa ser feito uma vez.",
    en: "Not published yet: your company doesn't have a Secure Publish address. Choose one at https://app.securepublish.work/app/hosting.html and try publishing again. You only need to do this once.",
  },
  noHostRename: {
    pt: "Ainda não renomeei: sua empresa não tem um endereço no Secure Publish. Escolha um em https://app.securepublish.work/app/hosting.html e tente de novo. Isso só precisa ser feito uma vez.",
    en: "Not renamed yet: your company doesn't have a Secure Publish address. Choose one at https://app.securepublish.work/app/hosting.html and try again. You only need to do this once.",
  },
  ignoredProjectMock: {
    pt: "Ignorei a opção mock do .secure-publish.json. O modo de teste só liga pela variável SECURE_PUBLISH_MOCK=1.",
    en: "Ignored the mock option in .secure-publish.json. Test mode only turns on with SECURE_PUBLISH_MOCK=1.",
  },
  removedMockFlag: {
    pt: runLines(
      "Não publiquei nada: a opção --mock não existe mais. Para testar sem publicar de verdade, rode:",
      `SECURE_PUBLISH_MOCK=1 ${NPX_CLI} publish <arquivo>`
    ),
    en: runLines(
      "Nothing was published: the --mock option no longer exists. To test without really publishing, run:",
      `SECURE_PUBLISH_MOCK=1 ${NPX_CLI} publish <file>`
    ),
  },
  mockPublishSuccess: {
    pt: "Publicado só nesta máquina, em modo de teste. Ninguém da empresa consegue abrir este link.",
    en: "Published only on this machine, in test mode. No one at your company can open this link.",
  },
  publishRetry: {
    pt: "Não consegui publicar agora. Tente de novo em instantes.",
    en: "Couldn't publish right now. Try again in a moment.",
  },
  renameRetry: {
    pt: "Não consegui alterar o nome agora. Tente de novo em instantes.",
    en: "Couldn't change the name right now. Try again in a moment.",
  },
  missingToEmail: {
    pt: "Diga quem pode abrir o link: inclua pelo menos um e-mail em --to, como --to ana@empresa.com.",
    en: "Say who can open the link: include at least one email in --to, like --to ana@company.com.",
  },
  doctorSignedIn: {
    pt: (email) => `Status: conectado como ${email}.`,
    en: (email) => (email ? `Status: signed in (${email}).` : "Status: signed in."),
  },
  doctorNotSignedIn: {
    pt: "Status: você ainda não entrou nesta máquina.",
    en: "Status: not signed in on this machine.",
  },
  revokeNetwork: {
    pt: "Não consegui falar com o Secure Publish. Verifique a conexão e tente de novo.",
    en: "Couldn't reach Secure Publish. Check your connection and try again.",
  },
  revokeForbidden: {
    pt: "Só quem publicou este link ou o dono da conta da empresa pode removê-lo.",
    en: "Only the person who published this link or the company account owner can remove it.",
  },
  revokeRetry: {
    pt: "Não consegui remover este link agora. Tente de novo em instantes.",
    en: "Couldn't remove this link right now. Try again in a moment.",
  },
};

const LOGIN_FAIL_KEYS = {
  login_failed: "loginFailed",
  login_expired: "loginExpired",
  login_denied: "loginDenied",
  login_no_pending: "loginNoPending",
};

export function message(key, lang, ...args) {
  const pack = MESSAGES[key];
  if (!pack) return "";
  const val = lang === "en" ? pack.en : pack.pt;
  return typeof val === "function" ? val(...args) : val;
}

export function loginFailMessage(code, lang) {
  const key = LOGIN_FAIL_KEYS[code] || LOGIN_FAIL_KEYS.login_failed;
  return message(key, lang);
}

export function langFromArgv(argv) {
  const list = Array.isArray(argv) ? argv : [];
  for (let i = 0; i < list.length; i++) {
    if (list[i] === "--lang") return list[i + 1] === "en" ? "en" : "pt";
  }
  return "pt";
}

export function thrownErrorLine(err, lang) {
  return `${message("errorPrefix", lang)} ${(err && err.message) || err}`;
}

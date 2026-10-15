"use strict";

/* CJS on purpose: the bin must print a clear error before any ESM import
 * that would crash on old Node. Keep this file ES5-parseable. */

var MIN_NODE_MAJOR = 20;

function checkNode(version, minMajor) {
  minMajor = minMajor === undefined ? MIN_NODE_MAJOR : minMajor;
  var raw = String(version || "");
  var major = parseInt(raw.replace(/^v/, ""), 10);
  var display = raw.charAt(0) === "v" ? raw : "v" + raw;
  if (isNaN(major) || major < minMajor) {
    return {
      ok: false,
      pt:
        "Este CLI precisa de Node.js " +
        minMajor +
        " ou mais novo (recomendado: 22 LTS). Você está em " +
        display +
        ". Instale o Node 22 LTS em https://nodejs.org e confira com: node -v",
      en:
        "This CLI requires Node.js " +
        minMajor +
        " or newer (recommended: 22 LTS). You are on " +
        display +
        ". Install Node 22 LTS from https://nodejs.org and check with: node -v",
    };
  }
  return { ok: true };
}

function enforceNodeVersion(version) {
  var result = checkNode(version, MIN_NODE_MAJOR);
  if (!result.ok) {
    console.error(result.pt);
    console.error(result.en);
    process.exit(1);
  }
}

module.exports = {
  MIN_NODE_MAJOR: MIN_NODE_MAJOR,
  checkNode: checkNode,
  enforceNodeVersion: enforceNodeVersion,
};

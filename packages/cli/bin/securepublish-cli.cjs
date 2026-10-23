#!/usr/bin/env node
"use strict";

var engines = require("../src/check-node.cjs");
engines.enforceNodeVersion(process.versions.node);

import("../src/cli.js")
  .then(function (mod) {
    return mod.main(process.argv.slice(2));
  })
  .catch(function (err) {
    return import("../src/messages.js").then(function (m) {
      var lang = m.langFromArgv(process.argv.slice(2));
      console.error(m.thrownErrorLine(err, lang));
      process.exit(1);
    });
  });

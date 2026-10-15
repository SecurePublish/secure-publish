#!/usr/bin/env node
"use strict";

var engines = require("../src/check-node.cjs");
engines.enforceNodeVersion(process.versions.node);

import("../src/cli.js")
  .then(function (mod) {
    return mod.main(process.argv.slice(2));
  })
  .catch(function (err) {
    console.error("Error: " + ((err && err.message) || err));
    process.exit(1);
  });

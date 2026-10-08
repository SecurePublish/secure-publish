#!/usr/bin/env node
import { main } from "../src/cli.js";
import { printCliError } from "../src/errors.js";

main(process.argv.slice(2)).catch((err) => {
  printCliError(err);
  process.exit(1);
});

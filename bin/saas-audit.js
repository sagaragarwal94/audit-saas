#!/usr/bin/env node
import { runCli } from "../src/cli.js";
import { UsageError } from "../src/config.js";

runCli(process.argv).catch((error) => {
  if (error instanceof UsageError) {
    console.error(`Error: ${error.message}\nRun: saas-audit help`);
    process.exitCode = 2;
    return;
  }
  console.error(error instanceof Error ? error.message : String(error));
  if (process.env.AUDITSAAS_DEBUG && error instanceof Error) console.error(error.stack);
  process.exitCode = 1;
});

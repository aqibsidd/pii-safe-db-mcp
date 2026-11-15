#!/usr/bin/env node
import { CLI_COMMANDS, runCli } from "./cli.js";

const args = process.argv.slice(2);

if (args.length > 0 && CLI_COMMANDS.has(args[0])) {
  process.exitCode = runCli(args);
} else {
  const { startServer } = await import("./main.js");
  startServer().catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}

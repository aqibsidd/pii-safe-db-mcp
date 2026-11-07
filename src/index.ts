#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { createAdapter, type DbAdapter } from "./db.js";
import { AuditLogger } from "./audit.js";
import { createServer, VERSION } from "./server.js";

const cfg = loadConfig();
let db: DbAdapter | undefined;
const getDb = async () => (db ??= await createAdapter(cfg));
const server = createServer(cfg, getDb, new AuditLogger(cfg.audit));

async function main() {
  await server.connect(new StdioServerTransport());
  console.error(
    `pii-safe-db-mcp ${VERSION} running on stdio (${cfg.dbType}, mask mode: ${cfg.pii.mode}, policy: ${
      cfg.policy.failClosed ? "fail-closed" : "permissive"
    }, audit: ${cfg.audit.target})`,
  );
}

async function shutdown() {
  await db?.close().catch(() => undefined);
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

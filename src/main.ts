import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { createAdapter, type DbAdapter } from "./db.js";
import { AuditLogger } from "./audit.js";
import { createServer, VERSION } from "./server.js";

export async function startServer(): Promise<void> {
  const cfg = loadConfig();
  let db: DbAdapter | undefined;
  const getDb = async () => (db ??= await createAdapter(cfg));
  const server = createServer(cfg, getDb, new AuditLogger(cfg.audit));

  const shutdown = async () => {
    await db?.close().catch(() => undefined);
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await server.connect(new StdioServerTransport());
  const mode = cfg.protection.current();
  console.error(
    `pii-safe-db-mcp ${VERSION} running on stdio (${cfg.dbType}, mask mode: ${cfg.pii.mode}, protection: ${
      mode.protected ? "ON" : "OFF"
    }, policy: ${cfg.store.path ?? "inline"} [${cfg.policy.failClosed ? "fail-closed" : "permissive"}], audit: ${cfg.audit.target})`,
  );
}

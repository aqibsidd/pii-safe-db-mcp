#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod";
import { loadConfig } from "./config.js";
import { createAdapter, type DbAdapter } from "./db.js";
import { classifyColumn, scrubText } from "./pii.js";
import { sanitiseResult } from "./sanitize.js";
import { assertNoBlockedColumns, assertReadOnly, isValidIdentifier, SqlGuardError } from "./sqlGuard.js";

const VERSION = "0.1.0";

const cfg = loadConfig();
let db: DbAdapter | undefined;
async function getDb(): Promise<DbAdapter> {
  db ??= await createAdapter(cfg);
  return db;
}

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function fail(err: unknown) {
  const raw = err instanceof Error ? err.message : String(err);
  // DB error messages can echo values (e.g. duplicate key 'john@x.com'); scrub them too.
  const msg = scrubText(raw, cfg.pii);
  const prefix = err instanceof SqlGuardError ? "Blocked" : "Error";
  return { content: [{ type: "text" as const, text: `${prefix}: ${msg}` }], isError: true };
}

const server = new McpServer({ name: "pii-safe-db-mcp", version: VERSION });

server.registerTool(
  "list_tables",
  {
    title: "List tables",
    description: `List tables and views in the connected ${cfg.dbType} database.`,
    inputSchema: { schema: z.string().optional().describe("Schema/database name. Defaults to the current one.") },
    annotations: { readOnlyHint: true },
  },
  async ({ schema }) => {
    try {
      if (schema && !isValidIdentifier(schema)) throw new SqlGuardError("Invalid schema name.");
      return ok(await (await getDb()).listTables(schema));
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  "describe_table",
  {
    title: "Describe table",
    description:
      "Show the columns of a table, their types, and whether each column is classified as PII (and will be masked) or blocked.",
    inputSchema: { table: z.string().describe("Table name, optionally schema-qualified (schema.table).") },
    annotations: { readOnlyHint: true },
  },
  async ({ table }) => {
    try {
      if (!isValidIdentifier(table)) throw new SqlGuardError("Invalid table name.");
      const cols = await (await getDb()).describeTable(table);
      if (cols.length === 0) return fail(new Error(`Table not found: ${table}`));
      const bare = table.split(".").pop()!;
      return ok(
        cols.map((c) => {
          const blocked = cfg.blockedColumns.has(c.name.toLowerCase());
          const pii = classifyColumn([c.name], bare, cfg.pii);
          return {
            ...c,
            default: c.default == null ? null : scrubText(String(c.default), cfg.pii),
            pii: pii ?? null,
            policy: blocked ? "blocked" : pii ? "masked" : "visible",
          };
        }),
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  "query",
  {
    title: "Run read-only SQL",
    description: [
      `Run a single read-only SQL statement (SELECT / WITH / SHOW / DESCRIBE / EXPLAIN) against ${cfg.dbType}.`,
      `Results are capped at ${cfg.maxRows} rows. PII is masked before results are returned:`,
      `columns recognised as PII (email, phone, name, address, Aadhaar, PAN, card numbers, passwords...) are replaced with`,
      cfg.pii.mode === "token"
        ? "stable tokens like <EMAIL_3f9a1c2b7d> (same input → same token, so you can still GROUP BY / COUNT DISTINCT / compare),"
        : cfg.pii.mode === "partial"
          ? "partially-masked values like j***@***.com or ******3210,"
          : "placeholders like [EMAIL],",
      "and PII patterns found inside other text columns are masked too.",
      "Prefer aggregates (COUNT, GROUP BY) over pulling raw rows. Use ? (MySQL) or $1 (Postgres) placeholders with `params`.",
    ].join(" "),
    inputSchema: {
      sql: z.string().describe("A single read-only SQL statement."),
      params: z
        .array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
        .optional()
        .describe("Bind parameters for placeholders."),
    },
    annotations: { readOnlyHint: true },
  },
  async ({ sql, params }) => {
    try {
      const safeSql = assertReadOnly(sql);
      assertNoBlockedColumns(safeSql, cfg.blockedColumns);
      const res = await (await getDb()).query(safeSql, params ?? []);
      for (const c of res.columns) {
        for (const n of [c.name, c.originalName]) {
          if (n && cfg.blockedColumns.has(n.toLowerCase())) {
            throw new SqlGuardError(`Column "${n}" is blocked by policy and cannot be queried.`);
          }
        }
      }
      return ok(sanitiseResult(res, cfg.pii, cfg.maxRows));
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  "pii_scan",
  {
    title: "Scan table for PII",
    description:
      "Sample rows from a table and report which columns contain PII (by column name and by detected values). Returns counts only, never values. Use it to discover PII hiding in free-text columns.",
    inputSchema: {
      table: z.string().describe("Table name, optionally schema-qualified."),
      sample_size: z.number().int().min(1).max(5000).optional().describe("Rows to sample (default 200)."),
    },
    annotations: { readOnlyHint: true },
  },
  async ({ table, sample_size }) => {
    try {
      if (!isValidIdentifier(table)) throw new SqlGuardError("Invalid table name.");
      const q = cfg.dbType === "mysql" ? "`" : '"';
      const ident = table.split(".").map((p) => `${q}${p}${q}`).join(".");
      const n = sample_size ?? 200;
      const res = await (await getDb()).query(`SELECT * FROM ${ident} LIMIT ${n}`);
      const bare = table.split(".").pop()!;
      const report = res.columns.map((c, i) => {
        const byName = classifyColumn([c.name, c.originalName], c.table ?? bare, cfg.pii);
        const stats: Record<string, number> = {};
        let nonNull = 0;
        for (const row of res.rows) {
          const v = row[i];
          if (v == null) continue;
          nonNull++;
          if (typeof v === "string" || typeof v === "number" || typeof v === "bigint") {
            const before: Record<string, number> = {};
            scrubText(String(v), cfg.pii, before);
            for (const k of Object.keys(before)) stats[k] = (stats[k] ?? 0) + 1;
          }
        }
        return {
          column: c.name,
          blocked: cfg.blockedColumns.has(c.name.toLowerCase()),
          piiByName: byName,
          valuesWithPii: stats,
          sampledNonNull: nonNull,
          recommendation:
            !byName && Object.keys(stats).length > 0
              ? `Inline PII found; it is masked at query time. Add "${bare}.${c.name}" to PII_EXTRA_COLUMNS to mask the whole column.`
              : undefined,
        };
      });
      return ok({ table, sampledRows: res.rows.length, columns: report });
    } catch (e) {
      return fail(e);
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`pii-safe-db-mcp ${VERSION} running on stdio (${cfg.dbType}, mask mode: ${cfg.pii.mode})`);
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

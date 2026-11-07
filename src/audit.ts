import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { normaliseSql } from "./sqlGuard.js";

export type Decision = "ALLOWED" | "BLOCKED" | "ERROR";

export interface AuditRecord {
  timestamp: string;
  actor: string;
  environment: string;
  database: string;
  db_type: string;
  tool: string;
  operation: string;
  decision: Decision;
  reason?: string;
  tables?: string[];
  duration_ms: number;
  rows_returned?: number;
  pii_detected?: number;
  masked_columns?: string[];
  query_fingerprint?: string;
  query_shape?: string;
  raw_pii_logged: false;
}

export interface AuditOptions {
  /** "stderr", "off", or a file path (JSON lines). */
  target: string;
  actor: string;
  environment: string;
  database: string;
  dbType: string;
  includeQueryShape: boolean;
}

export type AuditSink = (line: string) => void;

export class AuditLogger {
  private sink: AuditSink | null;

  constructor(private opts: AuditOptions, sink?: AuditSink) {
    if (sink) this.sink = sink;
    else if (opts.target === "off" || opts.target === "") this.sink = null;
    else if (opts.target === "stderr") this.sink = (l) => process.stderr.write(l + "\n");
    else this.sink = (l) => appendFileSync(opts.target, l + "\n", { mode: 0o600 });
  }

  /** Actor may be resolved lazily (MCP client name is only known after initialize). */
  actorResolver?: () => string | undefined;

  log(r: {
    tool: string;
    operation: string;
    decision: Decision;
    started: number;
    reason?: string;
    tables?: string[];
    rows?: number;
    pii?: number;
    maskedColumns?: string[];
    sql?: string;
  }): void {
    if (!this.sink) return;
    const shape = r.sql ? normaliseSql(r.sql) : undefined;
    const rec: AuditRecord = {
      timestamp: new Date().toISOString(),
      actor: this.opts.actor || this.actorResolver?.() || "unknown",
      environment: this.opts.environment,
      database: this.opts.database,
      db_type: this.opts.dbType,
      tool: r.tool,
      operation: r.operation,
      decision: r.decision,
      reason: r.reason,
      tables: r.tables,
      duration_ms: Date.now() - r.started,
      rows_returned: r.rows,
      pii_detected: r.pii,
      masked_columns: r.maskedColumns,
      query_fingerprint: shape ? createHash("sha256").update(shape).digest("hex").slice(0, 16) : undefined,
      query_shape: this.opts.includeQueryShape ? shape : undefined,
      raw_pii_logged: false,
    };
    try {
      this.sink(JSON.stringify(rec));
    } catch {
      // Never let audit failures break queries (but don't silently swallow forever).
      process.stderr.write("pii-safe-db-mcp: failed to write audit log\n");
    }
  }
}

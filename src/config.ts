import { randomBytes } from "node:crypto";
import type { MaskMode, PiiOptions } from "./pii.js";
import { Policy, PolicyStore } from "./policy.js";
import type { AuditOptions } from "./audit.js";
import { policyPath, statePath } from "./paths.js";
import { ProtectionController } from "./state.js";

export type DbType = "mysql" | "postgres";

export interface Config {
  dbType: DbType;
  connectionString?: string;
  host: string;
  port: number;
  user?: string;
  password?: string;
  database?: string;
  ssl: boolean;
  maxRows: number;
  timeoutMs: number;
  blockedColumns: Set<string>;
  /** Hot-reloading policy (re-read when the policy file changes). */
  store: PolicyStore;
  /** Protection on/off controller. */
  protection: ProtectionController;
  /** Current PII options (getter → latest policy snapshot). */
  readonly pii: PiiOptions;
  /** Current policy (getter → latest policy snapshot). */
  readonly policy: Policy;
  audit: AuditOptions;
}

function list(v: string | undefined): Set<string> {
  return new Set(
    (v ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

function bool(v: string | undefined, dflt: boolean): boolean {
  if (v === undefined || v === "") return dflt;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

function databaseName(url: string | undefined, name: string | undefined): string {
  if (name) return name;
  if (!url) return "unknown";
  try {
    return decodeURIComponent(new URL(url).pathname.replace(/^\//, "")) || "unknown";
  } catch {
    return "unknown";
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const url = env.DATABASE_URL;
  let dbType = (env.DB_TYPE ?? "").toLowerCase() as DbType | "postgresql" | "";
  if (!dbType && url) {
    if (/^mysql2?:/i.test(url)) dbType = "mysql";
    else if (/^postgres(ql)?:/i.test(url)) dbType = "postgres";
  }
  if (dbType === "postgresql") dbType = "postgres";
  if (dbType !== "mysql" && dbType !== "postgres") {
    throw new Error("Set DB_TYPE to 'mysql' or 'postgres', or provide DATABASE_URL (mysql://... or postgres://...).");
  }

  const mode = (env.PII_MASK_MODE ?? "token").toLowerCase() as MaskMode;
  if (!["token", "partial", "redact"].includes(mode)) {
    throw new Error("PII_MASK_MODE must be one of: token, partial, redact");
  }

  const blockedColumns = list(env.PII_BLOCKED_COLUMNS);
  const basePii: PiiOptions = {
    mode,
    secret: env.PII_TOKEN_SECRET || randomBytes(32).toString("hex"),
    allowColumns: list(env.PII_ALLOW_COLUMNS),
    extraColumns: list(env.PII_EXTRA_COLUMNS),
    scanValues: bool(env.PII_SCAN_VALUES, true),
  };

  const store = new PolicyStore({
    inline: env.PII_POLICY,
    path: policyPath(env),
    basePii,
    globalBlocked: blockedColumns,
    extraAllowed: list(env.ALLOWED_TABLES),
    extraDenied: list(env.DENIED_TABLES),
    failClosed: env.POLICY_FAIL_CLOSED !== undefined ? bool(env.POLICY_FAIL_CLOSED, true) : undefined,
  });

  const protection = new ProtectionController({
    envMode: env.PII_PROTECTION,
    allowUnprotected: bool(env.PII_ALLOW_UNPROTECTED_MODE, false),
    statePath: statePath(env),
  });

  return {
    dbType,
    connectionString: url,
    host: env.DB_HOST ?? "localhost",
    port: Number(env.DB_PORT ?? (dbType === "mysql" ? 3306 : 5432)),
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    database: env.DB_NAME,
    ssl: bool(env.DB_SSL, false),
    maxRows: Math.max(1, Number(env.MAX_ROWS ?? 200)),
    timeoutMs: Math.max(1000, Number(env.QUERY_TIMEOUT_MS ?? 15000)),
    blockedColumns,
    store,
    protection,
    get pii() {
      return store.current().pii;
    },
    get policy() {
      return store.current().policy;
    },
    audit: {
      target: env.AUDIT_LOG ?? "stderr",
      actor: env.AUDIT_ACTOR ?? "",
      environment: env.AUDIT_ENVIRONMENT ?? "default",
      database: databaseName(url, env.DB_NAME),
      dbType,
      includeQueryShape: bool(env.AUDIT_QUERY_SHAPE, true),
    },
  };
}

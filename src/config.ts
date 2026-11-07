import { randomBytes } from "node:crypto";
import type { MaskMode, PiiOptions } from "./pii.js";
import { compileCustomPatterns, Policy, readPolicyFile } from "./policy.js";
import type { AuditOptions } from "./audit.js";

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
  pii: PiiOptions;
  policy: Policy;
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

  const policyFile = readPolicyFile(env.PII_POLICY_FILE, env.PII_POLICY);
  const custom = compileCustomPatterns(policyFile.custom_patterns);
  const blockedColumns = list(env.PII_BLOCKED_COLUMNS);

  const pii: PiiOptions = {
    mode,
    secret: env.PII_TOKEN_SECRET || randomBytes(32).toString("hex"),
    allowColumns: list(env.PII_ALLOW_COLUMNS),
    extraColumns: list(env.PII_EXTRA_COLUMNS),
    scanValues: bool(env.PII_SCAN_VALUES, true),
    customRules: custom.valueRules,
    customColumns: custom.columnTypes,
  };

  if (env.POLICY_FAIL_CLOSED !== undefined) policyFile.fail_closed = bool(env.POLICY_FAIL_CLOSED, true);

  const policy = new Policy(policyFile, pii, blockedColumns, list(env.ALLOWED_TABLES), list(env.DENIED_TABLES));

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
    pii,
    policy,
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

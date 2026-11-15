/**
 * Human-facing CLI. Used directly in a terminal, or through the Claude Code
 * slash commands installed by `install-commands` (/pii-on, /pii-off, /pii-add ...).
 *
 *   pii-safe-db-mcp mode status|on|off [--for 30m]
 *   pii-safe-db-mcp policy path|show|init
 *   pii-safe-db-mcp policy add <table> <col,col> [--strict|--no-filter|--no-join|--no-group|--no-sort]
 *   pii-safe-db-mcp policy block <table> <col,col>
 *   pii-safe-db-mcp policy remove <table> <col,col>
 *   pii-safe-db-mcp policy allow-table <t,t> | deny-table <t,t>
 *   pii-safe-db-mcp policy merge '<json>'
 *   pii-safe-db-mcp install-commands [--project]
 *
 * Global options: --file <policy.json>  --state <state.json>
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir, userInfo } from "node:os";
import { policyPath, statePath } from "./paths.js";
import { validatePolicyFile, type PolicyFile, type TablePolicy } from "./policy.js";
import { parseDuration, readState, writeJsonAtomic, writeState } from "./state.js";

export const CLI_COMMANDS = new Set(["mode", "policy", "install-commands", "help", "--help", "-h", "--version", "-v"]);

const VERSION = "0.3.0";
const IDENT = /^[A-Za-z_][\w$]*$/;
const TABLE = /^[A-Za-z_][\w$]*(\.[A-Za-z_][\w$]*)?$/;
const TABLE_OR_WILDCARD = /^[A-Za-z_][\w$]*(\.([A-Za-z_][\w$]*|\*))?$/;

class CliError extends Error {}

interface Parsed {
  args: string[];
  flags: Map<string, string | true>;
}

function parse(argv: string[]): Parsed {
  const args: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2);
      if (v !== undefined) flags.set(k, v);
      else if (["file", "state", "for"].includes(k) && argv[i + 1] !== undefined) flags.set(k, argv[++i]);
      else flags.set(k, true);
    } else args.push(a);
  }
  return { args, flags };
}

function envFor(p: Parsed): NodeJS.ProcessEnv {
  const env = { ...process.env };
  const file = p.flags.get("file");
  const state = p.flags.get("state");
  if (typeof file === "string") env.PII_POLICY_FILE = file;
  if (typeof state === "string") env.PII_STATE_FILE = state;
  return env;
}

/** Split "a,b c" style lists (commas and/or spaces). */
function splitList(parts: string[]): string[] {
  return parts
    .join(",")
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function loadPolicy(path: string): PolicyFile {
  if (!existsSync(path)) return {};
  const raw = readFileSync(path, "utf8").trim();
  if (!raw) return {};
  try {
    return validatePolicyFile(JSON.parse(raw));
  } catch (e) {
    throw new CliError(`Cannot read ${path}: ${(e as Error).message}. Fix the file first (nothing was changed).`);
  }
}

function savePolicy(path: string, p: PolicyFile): void {
  validatePolicyFile(p);
  writeJsonAtomic(path, p);
}

const uniq = (xs: string[]) => [...new Set(xs)];
const lc = (s: string) => s.toLowerCase();

function tableEntry(p: PolicyFile, table: string): TablePolicy {
  p.tables ??= {};
  const key = Object.keys(p.tables).find((k) => lc(k) === lc(table)) ?? lc(table);
  p.tables[key] ??= {};
  return p.tables[key];
}

/* --------------------------------- mode --------------------------------- */

function cmdMode(p: Parsed): string {
  const env = envFor(p);
  const path = statePath(env);
  const sub = p.args[1] ?? "status";
  const by = (() => {
    try {
      return userInfo().username;
    } catch {
      return "unknown";
    }
  })();
  const note =
    "Note: OFF only takes effect if the MCP server runs with PII_ALLOW_UNPROTECTED_MODE=true. Check with the protection_status tool.";

  if (sub === "off") {
    const ms = parseDuration(typeof p.flags.get("for") === "string" ? (p.flags.get("for") as string) : p.args[2]);
    const now = new Date();
    const until = new Date(now.getTime() + ms);
    writeState(path, { mode: "off", until: until.toISOString(), changed_at: now.toISOString(), changed_by: by });
    return [
      `⚠️  PII protection OFF until ${until.toLocaleTimeString()} (${Math.round(ms / 60000)} min). Results will be RAW and unmasked.`,
      "   It switches back ON automatically. Turn it on now with /pii-on.",
      `   ${note}`,
    ].join("\n");
  }
  if (sub === "on") {
    writeState(path, { mode: "on", changed_at: new Date().toISOString(), changed_by: by });
    return "🔒 PII protection ON. Results are masked and the query policy is enforced.";
  }
  if (sub === "status") {
    const s = readState(path);
    const off = s?.mode === "off" && s.until && Date.parse(s.until) > Date.now();
    return off
      ? `⚠️  Requested: OFF until ${new Date(s!.until!).toLocaleTimeString()} (set by ${s!.changed_by ?? "unknown"}).\n   ${note}`
      : "🔒 Requested: ON (default). PII is masked and the policy is enforced.";
  }
  throw new CliError(`Unknown mode command "${sub}". Use: mode status | on | off [--for 30m]`);
}

/* -------------------------------- policy -------------------------------- */

function describePolicy(p: PolicyFile, path: string, only?: string): string {
  const out: string[] = [`Policy file: ${path}${existsSync(path) ? "" : " (not created yet)"}`];
  if (!only) {
    out.push(`Allowed tables: ${p.allowed_tables?.length ? p.allowed_tables.join(", ") : "(all)"}`);
    if (p.denied_tables?.length) out.push(`Denied tables:  ${p.denied_tables.join(", ")}`);
  }
  const tables = Object.entries(p.tables ?? {}).filter(([t]) => !only || lc(t) === lc(only));
  if (tables.length === 0) out.push(only ? `No rules for table "${only}".` : "No table rules yet. Add some with /pii-add <table> <columns>.");
  for (const [t, tp] of tables) {
    const off = (["allow_filtering", "allow_joining", "allow_grouping", "allow_sorting"] as const)
      .filter((k) => tp[k] === false)
      .map((k) => k.replace("allow_", "no-"));
    out.push(`• ${t}`);
    if (tp.sensitive_columns?.length) out.push(`    masked:  ${tp.sensitive_columns.join(", ")}`);
    if (tp.blocked_columns?.length) out.push(`    blocked: ${tp.blocked_columns.join(", ")}`);
    if (off.length) out.push(`    rules:   ${off.join(", ")}`);
  }
  if (!only && p.custom_patterns?.length) out.push(`Custom patterns: ${p.custom_patterns.map((c) => c.name).join(", ")}`);
  return out.join("\n");
}

function cmdPolicy(p: Parsed): string {
  const env = envFor(p);
  const path = policyPath(env);
  const sub = p.args[1] ?? "show";
  const live = "Live on the next query — no reconnect needed.";

  if (sub === "path") return path;
  if (sub === "show") return describePolicy(loadPolicy(path), path, p.args[2]);
  if (sub === "init") {
    if (existsSync(path)) return `Policy file already exists: ${path}`;
    savePolicy(path, { allowed_tables: [], denied_tables: [], tables: {} });
    return `Created ${path}`;
  }

  if (sub === "add" || sub === "block" || sub === "remove") {
    const table = p.args[2];
    const cols = splitList(p.args.slice(3));
    if (!table || !TABLE.test(table)) throw new CliError(`Usage: policy ${sub} <table> <col1,col2,...>`);
    if (cols.length === 0) throw new CliError(`No columns given. Usage: policy ${sub} ${table} <col1,col2,...>`);
    const bad = cols.filter((c) => !IDENT.test(c));
    if (bad.length) throw new CliError(`Invalid column name(s): ${bad.join(", ")}`);
    const lcCols = cols.map(lc);

    const pol = loadPolicy(path);
    const t = tableEntry(pol, table);
    let msg: string;
    if (sub === "add") {
      t.sensitive_columns = uniq([...(t.sensitive_columns ?? []), ...lcCols]);
      const strict = p.flags.has("strict");
      const set: string[] = [];
      for (const [flag, key] of [
        ["no-filter", "allow_filtering"],
        ["no-join", "allow_joining"],
        ["no-group", "allow_grouping"],
        ["no-sort", "allow_sorting"],
      ] as const) {
        if (strict || p.flags.has(flag)) {
          t[key] = false;
          set.push(flag);
        }
      }
      msg = `✅ ${table}: now masking ${lcCols.join(", ")}${set.length ? ` (rules: ${set.join(", ")})` : ""}.`;
    } else if (sub === "block") {
      t.blocked_columns = uniq([...(t.blocked_columns ?? []), ...lcCols]);
      msg = `⛔ ${table}: ${lcCols.join(", ")} can no longer be queried at all.`;
    } else {
      const before = (t.sensitive_columns?.length ?? 0) + (t.blocked_columns?.length ?? 0);
      t.sensitive_columns = (t.sensitive_columns ?? []).filter((c) => !lcCols.includes(lc(c)));
      t.blocked_columns = (t.blocked_columns ?? []).filter((c) => !lcCols.includes(lc(c)));
      const after = t.sensitive_columns.length + t.blocked_columns.length;
      if (!t.sensitive_columns.length) delete t.sensitive_columns;
      if (!t.blocked_columns.length) delete t.blocked_columns;
      msg =
        before === after
          ? `Nothing removed: ${lcCols.join(", ")} not listed for ${table}. (Columns auto-detected by name are always masked; use PII_ALLOW_COLUMNS to override.)`
          : `↩️  ${table}: removed ${lcCols.join(", ")} from the policy.`;
    }
    savePolicy(path, pol);
    return `${msg}\n   ${live}\n   File: ${path}`;
  }

  if (sub === "allow-table" || sub === "deny-table") {
    const tables = splitList(p.args.slice(2)).map(lc);
    if (!tables.length) throw new CliError(`Usage: policy ${sub} <table1,table2,...>  (schema.table and schema.* work too)`);
    const bad = tables.filter((t) => !TABLE_OR_WILDCARD.test(t));
    if (bad.length) throw new CliError(`Invalid table name(s): ${bad.join(", ")}`);
    const pol = loadPolicy(path);
    const key = sub === "allow-table" ? "allowed_tables" : "denied_tables";
    pol[key] = uniq([...(pol[key] ?? []), ...tables]);
    savePolicy(path, pol);
    const extra =
      sub === "allow-table" && pol.allowed_tables!.length === tables.length
        ? "\n   Note: an allowlist is now active — tables not listed are blocked."
        : "";
    return `✅ ${key.replace("_", " ")}: ${pol[key]!.join(", ")}${extra}\n   ${live}`;
  }

  if (sub === "merge") {
    const raw = p.args.slice(2).join(" ").trim();
    if (!raw) throw new CliError(`Usage: policy merge '{"tables":{"customers":{"sensitive_columns":["name"]}}}'`);
    let add: PolicyFile;
    try {
      const parsed = JSON.parse(raw);
      // Accept either a full policy or just a { "table": {...} } map.
      add = validatePolicyFile(
        parsed.tables || parsed.allowed_tables || parsed.denied_tables || parsed.custom_patterns || parsed.default
          ? parsed
          : { tables: parsed },
      );
    } catch (e) {
      throw new CliError(`Invalid JSON: ${(e as Error).message}`);
    }
    const pol = loadPolicy(path);
    for (const k of ["allowed_tables", "denied_tables"] as const) {
      if (add[k]) pol[k] = uniq([...(pol[k] ?? []), ...add[k]!.map(lc)]);
    }
    for (const [tname, tp] of Object.entries(add.tables ?? {})) {
      const t = tableEntry(pol, tname);
      if (tp.sensitive_columns) t.sensitive_columns = uniq([...(t.sensitive_columns ?? []), ...tp.sensitive_columns.map(lc)]);
      if (tp.blocked_columns) t.blocked_columns = uniq([...(t.blocked_columns ?? []), ...tp.blocked_columns.map(lc)]);
      for (const r of ["allow_select", "allow_filtering", "allow_joining", "allow_grouping", "allow_sorting"] as const) {
        if (tp[r] !== undefined) t[r] = tp[r];
      }
    }
    if (add.custom_patterns) {
      const names = new Set(add.custom_patterns.map((c) => c.name));
      pol.custom_patterns = [...(pol.custom_patterns ?? []).filter((c) => !names.has(c.name)), ...add.custom_patterns];
    }
    if (add.default) pol.default = { ...(pol.default ?? {}), ...add.default };
    for (const k of ["fail_closed", "treat_detected_pii_as_sensitive"] as const) {
      if (add[k] !== undefined) pol[k] = add[k];
    }
    savePolicy(path, pol);
    return `✅ Merged into ${path}\n   ${live}\n\n${describePolicy(pol, path)}`;
  }

  throw new CliError(`Unknown policy command "${sub}". Run: pii-safe-db-mcp help`);
}

/* ---------------------------- install-commands ---------------------------- */

interface SlashCommand {
  name: string;
  description: string;
  hint?: string;
  run: string;
  /** Loosening commands must never be triggered by the model itself. */
  humanOnly: boolean;
  after: string;
}

function installCommands(p: Parsed): string {
  const project = p.flags.has("project");
  const dir = project ? resolve(".claude/commands") : join(homedir(), ".claude", "commands");
  const pkg = `pii-safe-db-mcp@^${VERSION.split(".").slice(0, 2).join(".")}.0`;
  const extra = [
    typeof p.flags.get("file") === "string" ? `--file "${resolve(p.flags.get("file") as string)}"` : process.env.PII_POLICY_FILE ? `--file "${resolve(process.env.PII_POLICY_FILE)}"` : "",
    typeof p.flags.get("state") === "string" ? `--state "${resolve(p.flags.get("state") as string)}"` : process.env.PII_STATE_FILE ? `--state "${resolve(process.env.PII_STATE_FILE)}"` : "",
  ]
    .filter(Boolean)
    .join(" ");
  const cli = `npx -y ${pkg}`;
  const tail = extra ? ` ${extra}` : "";
  const report = "Show the command output above to the user verbatim in a short code block, then stop. Do not run any other commands or tools.";

  const cmds: SlashCommand[] = [
    { name: "pii-status", description: "Show PII protection mode and the current masking policy", run: `${cli} mode status${tail} && ${cli} policy show${tail}`, humanOnly: false, after: report },
    { name: "pii-on", description: "Turn PII protection ON (mask results, enforce policy)", run: `${cli} mode on${tail}`, humanOnly: false, after: report },
    { name: "pii-off", description: "Turn PII protection OFF temporarily (raw data; auto-expires, default 30m)", hint: "[30m|2h]", run: `${cli} mode off "$ARGUMENTS"${tail}`, humanOnly: true, after: report },
    { name: "pii-add", description: "Mask more columns: /pii-add <table> <col1,col2> [--strict]", hint: "<table> <col1,col2,...> [--strict|--no-filter|--no-join|--no-group|--no-sort]", run: `${cli} policy add "$ARGUMENTS"${tail}`, humanOnly: false, after: report },
    { name: "pii-block", description: "Block columns completely: /pii-block <table> <col1,col2>", hint: "<table> <col1,col2,...>", run: `${cli} policy block "$ARGUMENTS"${tail}`, humanOnly: false, after: report },
    { name: "pii-remove", description: "Stop masking/blocking columns: /pii-remove <table> <col1,col2>", hint: "<table> <col1,col2,...>", run: `${cli} policy remove "$ARGUMENTS"${tail}`, humanOnly: true, after: report },
    { name: "pii-tables", description: "Allow or deny tables: /pii-tables allow crm.*,loans  or  /pii-tables deny salaries", hint: "allow|deny <table1,table2,...>", run: `${cli} policy tables "$ARGUMENTS"${tail}`, humanOnly: true, after: report },
    { name: "pii-json", description: "Merge a JSON snippet into the policy: /pii-json {\"customers\":{\"sensitive_columns\":[\"name\"]}}", hint: "<json>", run: `${cli} policy merge '$ARGUMENTS'${tail}`, humanOnly: true, after: report },
  ];

  mkdirSync(dir, { recursive: true });
  for (const c of cmds) {
    const front = [
      "---",
      `description: ${c.description.replace(/\n/g, " ")}`,
      c.hint ? `argument-hint: ${c.hint}` : "",
      `allowed-tools: Bash(npx -y ${pkg}:*)`,
      c.humanOnly ? "disable-model-invocation: true" : "",
      "---",
    ]
      .filter(Boolean)
      .join("\n");
    writeFileSync(join(dir, `${c.name}.md`), `${front}\n\n!\`${c.run}\`\n\n${c.after}\n`);
  }
  return [
    `Installed ${cmds.length} slash commands in ${dir}:`,
    ...cmds.map((c) => `  /${c.name.padEnd(11)} ${c.description}`),
    "",
    "Restart Claude Code (or open a new session) to see them. Type / to list.",
  ].join("\n");
}

/* --------------------------------- main --------------------------------- */

const HELP = `pii-safe-db-mcp ${VERSION}

Run with no arguments to start the MCP server (stdio).

Protection mode
  mode status                         show the requested mode
  mode on                             mask results + enforce the policy (default)
  mode off [--for 30m|2h]             raw results, auto-expires (max 8h).
                                      Needs PII_ALLOW_UNPROTECTED_MODE=true on the server.
Policy
  policy show [table]                 show the policy
  policy path                         print the policy file path
  policy init                         create an empty policy file
  policy add <table> <cols> [--strict|--no-filter|--no-join|--no-group|--no-sort]
  policy block <table> <cols>         columns can never be queried
  policy remove <table> <cols>        stop masking/blocking (listed columns only)
  policy allow-table <tables>         add to the allowlist (schema.* works)
  policy deny-table <tables>          add to the denylist
  policy merge '<json>'               merge a policy JSON snippet

Claude Code
  install-commands [--project]        add /pii-status /pii-on /pii-off /pii-add /pii-block
                                      /pii-remove /pii-tables /pii-json slash commands

Options: --file <policy.json>  --state <state.json>
Defaults: ~/.config/pii-safe-db/policy.json and state.json (or PII_POLICY_FILE / PII_STATE_FILE / PII_CONFIG_DIR)`;

export function runCli(argv: string[]): number {
  // Slash commands pass all user arguments as ONE quoted string (so shells never
  // glob "crm.*"); split it here. JSON for `policy merge` is kept intact.
  if (!(argv[0] === "policy" && argv[1] === "merge")) {
    argv = argv.flatMap((a) => (/\s/.test(a) ? a.trim().split(/\s+/) : [a])).filter((a) => a !== "");
  }
  const p = parse(argv);
  try {
    const cmd = p.args[0] ?? (p.flags.has("version") || p.flags.has("v") ? "--version" : "help");
    let out: string;
    if (cmd === "mode") out = cmdMode(p);
    else if (cmd === "policy") {
      // "policy tables allow x,y" → allow-table
      if (p.args[1] === "tables") {
        const action = p.args[2];
        if (action !== "allow" && action !== "deny") throw new CliError("Usage: /pii-tables allow|deny <table1,table2,...>");
        p.args.splice(1, 2, `${action}-table`);
      }
      out = cmdPolicy(p);
    } else if (cmd === "install-commands") out = installCommands(p);
    else if (cmd === "--version" || cmd === "-v") out = VERSION;
    else out = HELP;
    process.stdout.write(out + "\n");
    return 0;
  } catch (e) {
    process.stderr.write(`Error: ${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  }
}

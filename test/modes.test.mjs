/**
 * Protection on/off mode, policy hot-reload, and the CLI / slash commands.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadConfig } from "../dist/config.js";
import { createServer } from "../dist/server.js";
import { AuditLogger } from "../dist/audit.js";

const CLI = new URL("../dist/index.js", import.meta.url).pathname;

const fakeDb = {
  kind: "postgres",
  async query(sql) {
    if (/id = 999/.test(sql)) throw new Error("Duplicate entry 'Ravi Kumar' for key 'customers.full_name'");
    return {
      columns: [
        { name: "id", originalName: "id", table: "customers" },
        { name: "full_name", originalName: "full_name", table: "customers" },
        { name: "customer_ref", originalName: "customer_ref", table: "customers" },
        { name: "city", originalName: "city", table: "customers" },
      ],
      rows: [[1, "Ravi Kumar", "CUST-RK-001", "Pune"]],
    };
  },
  async listTables() {
    return [{ schema: "public", name: "customers", type: "BASE TABLE" }];
  },
  async describeTable() {
    return [{ name: "id", dataType: "int", nullable: false }];
  },
  async close() {},
};

function freshDir() {
  return mkdtempSync(join(tmpdir(), "pii-safe-test-"));
}

function cli(dir, ...args) {
  return execFileSync("node", [CLI, ...args], { env: { ...process.env, PII_CONFIG_DIR: dir }, encoding: "utf8" });
}

async function startServer(dir, extraEnv = {}) {
  const env = { DATABASE_URL: "postgres://u:p@h:5432/customer_db", PII_CONFIG_DIR: dir, ...extraEnv };
  const cfg = loadConfig(env);
  const audit = [];
  const server = createServer(cfg, async () => fakeDb, new AuditLogger(cfg.audit, (l) => audit.push(JSON.parse(l))));
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "modes-test", version: "1" });
  await client.connect(ct);
  const call = async (name, args = {}) => {
    const r = await client.callTool({ name, arguments: args });
    return { text: r.content.map((c) => c.text).join("\n"), isError: !!r.isError };
  };
  return { call, audit, close: () => client.close() };
}

const SELECT = { sql: "SELECT id, full_name, customer_ref, city FROM customers" };

describe("protection mode", () => {
  test("ON by default: masked", async () => {
    const s = await startServer(freshDir());
    const r = await s.call("query", SELECT);
    assert.ok(!r.text.includes("Ravi Kumar"), r.text);
    assert.match(r.text, /<NAME_/);
    assert.match((await s.call("protection_status")).text, /"protection": "on"/);
    await s.close();
  });

  test("OFF request is ignored unless PII_ALLOW_UNPROTECTED_MODE=true", async () => {
    const dir = freshDir();
    cli(dir, "mode", "off", "--for", "10m");
    const s = await startServer(dir);
    const r = await s.call("query", SELECT);
    assert.ok(!r.text.includes("Ravi Kumar"), "must stay masked");
    const st = (await s.call("protection_status")).text;
    assert.match(st, /"protection": "on"/);
    assert.match(st, /PII_ALLOW_UNPROTECTED_MODE is not enabled/);
    assert.ok(s.audit.some((a) => a.operation === "PROTECTION_OFF_REQUEST" && a.decision === "BLOCKED"));
    await s.close();
  });

  test("OFF (allowed): raw data like a normal MCP, banner shown, audited, still read-only", async () => {
    const dir = freshDir();
    const s = await startServer(dir, { PII_ALLOW_UNPROTECTED_MODE: "true" });
    assert.ok(!(await s.call("query", SELECT)).text.includes("Ravi Kumar"));

    cli(dir, "mode", "off", "30m");
    const r = await s.call("query", SELECT);
    assert.ok(r.text.includes("Ravi Kumar"), r.text);
    assert.match(r.text, /PII protection is OFF until/);

    // still read-only
    const del = await s.call("query", { sql: "DELETE FROM customers" });
    assert.equal(del.isError, true);

    // raw DB errors to the client, but never into the audit log
    const err = await s.call("query", { sql: "SELECT id FROM customers WHERE id = 999" });
    assert.match(err.text, /Ravi Kumar/);

    assert.ok(s.audit.some((a) => a.operation === "PROTECTION_OFF" && a.protection === "off"));
    assert.ok(s.audit.filter((a) => a.tool === "query").some((a) => a.protection === "off"));
    assert.ok(!JSON.stringify(s.audit).includes("Ravi"), "audit log must never contain raw values");

    cli(dir, "mode", "on");
    const back = await s.call("query", SELECT);
    assert.ok(!back.text.includes("Ravi Kumar"));
    assert.ok(s.audit.some((a) => a.operation === "PROTECTION_ON"));
    await s.close();
  });

  test("OFF expires automatically and tampered state files are ignored", async () => {
    const dir = freshDir();
    const s = await startServer(dir, { PII_ALLOW_UNPROTECTED_MODE: "true" });
    const now = Date.now();
    writeFileSync(join(dir, "state.json"), JSON.stringify({ mode: "off", changed_at: new Date(now - 3600e3).toISOString(), until: new Date(now - 1000).toISOString() }));
    assert.ok(!(await s.call("query", SELECT)).text.includes("Ravi Kumar"), "expired → ON");
    writeFileSync(join(dir, "state.json"), JSON.stringify({ mode: "off", changed_at: new Date(now).toISOString(), until: new Date(now + 48 * 3600e3).toISOString() }));
    assert.ok(!(await s.call("query", SELECT)).text.includes("Ravi Kumar"), "longer than 8h → ignored");
    await s.close();
  });

  test("PII_PROTECTION=off env needs the allow flag too", async () => {
    const a = await startServer(freshDir(), { PII_PROTECTION: "off" });
    assert.ok(!(await a.call("query", SELECT)).text.includes("Ravi Kumar"));
    await a.close();
    const b = await startServer(freshDir(), { PII_PROTECTION: "off", PII_ALLOW_UNPROTECTED_MODE: "true" });
    assert.ok((await b.call("query", SELECT)).text.includes("Ravi Kumar"));
    await b.close();
  });

  test("protection cannot be changed through MCP tools", async () => {
    const s = await startServer(freshDir());
    const { text } = await s.call("protection_status");
    assert.match(text, /protection_status|"protection"/);
    // There is no tool that turns protection off.
    await s.close();
  });
});

describe("policy hot-reload", () => {
  test("columns added with the CLI are masked on the next query, no restart", async () => {
    const dir = freshDir();
    const s = await startServer(dir);
    const before = await s.call("query", SELECT);
    assert.ok(before.text.includes("CUST-RK-001"), "customer_ref is not PII by name");

    cli(dir, "policy", "add", "customers customer_ref");
    const after = await s.call("query", SELECT);
    assert.ok(!after.text.includes("CUST-RK-001"), after.text);
    assert.match(after.text, /<PII_/);

    cli(dir, "policy", "block", "customers", "city");
    assert.equal((await s.call("query", SELECT)).isError, true, "blocked column rejected");
    await s.close();
  });

  test("a broken policy edit never weakens protection", async () => {
    const dir = freshDir();
    cli(dir, "policy", "add", "customers", "customer_ref");
    const s = await startServer(dir);
    writeFileSync(join(dir, "policy.json"), "{ this is not json");
    const r = await s.call("query", SELECT);
    assert.ok(!r.text.includes("CUST-RK-001"), "previous policy still applies");
    assert.match((await s.call("protection_status")).text, /Invalid policy file/);
    await s.close();
  });
});

describe("CLI", () => {
  test("add / block / remove / tables / merge / show", () => {
    const dir = freshDir();
    cli(dir, "policy", "add", "customers full_name,mobile_no pan_no --strict");
    cli(dir, "policy", "block", "customers kyc_url");
    cli(dir, "policy", "tables", "allow customers,loans,crm.*");
    cli(dir, "policy", "merge", '{"loans":{"sensitive_columns":["Borrower_Name"],"allow_joining":false}}');
    cli(dir, "policy", "remove", "customers mobile_no");
    const p = JSON.parse(readFileSync(join(dir, "policy.json"), "utf8"));
    assert.deepEqual(p.tables.customers.sensitive_columns, ["full_name", "pan_no"]);
    assert.deepEqual(p.tables.customers.blocked_columns, ["kyc_url"]);
    assert.equal(p.tables.customers.allow_joining, false);
    assert.deepEqual(p.allowed_tables, ["customers", "loans", "crm.*"]);
    assert.deepEqual(p.tables.loans.sensitive_columns, ["borrower_name"]);
    assert.match(cli(dir, "policy", "show"), /masked:\s+full_name, pan_no/);
  });

  test("rejects bad input without touching the file", () => {
    const dir = freshDir();
    cli(dir, "policy", "add", "customers", "a");
    const before = readFileSync(join(dir, "policy.json"), "utf8");
    for (const args of [["policy", "add", "customers bad-col"], ["policy", "add", "x;rm a"], ["policy", "merge", "{nope"], ["mode", "off", "9h"]]) {
      assert.throws(() => execFileSync("node", [CLI, ...args], { env: { ...process.env, PII_CONFIG_DIR: dir }, stdio: "pipe" }), args.join(" "));
    }
    assert.equal(readFileSync(join(dir, "policy.json"), "utf8"), before);
  });

  test("install-commands writes slash commands; loosening ones are human-only", () => {
    const dir = freshDir();
    const home = freshDir();
    execFileSync("node", [CLI, "install-commands"], { env: { ...process.env, HOME: home, PII_CONFIG_DIR: dir }, encoding: "utf8" });
    const cmdDir = join(home, ".claude", "commands");
    const files = readdirSync(cmdDir).sort();
    assert.deepEqual(files, ["pii-add.md", "pii-block.md", "pii-json.md", "pii-off.md", "pii-on.md", "pii-remove.md", "pii-status.md", "pii-tables.md"]);
    const off = readFileSync(join(cmdDir, "pii-off.md"), "utf8");
    assert.match(off, /disable-model-invocation: true/);
    assert.match(off, /mode off "\$ARGUMENTS"/);
    for (const f of ["pii-remove.md", "pii-tables.md", "pii-json.md"]) {
      assert.match(readFileSync(join(cmdDir, f), "utf8"), /disable-model-invocation: true/, f);
    }
    assert.doesNotMatch(readFileSync(join(cmdDir, "pii-add.md"), "utf8"), /disable-model-invocation/);
  });
});

/**
 * Security regression: drive the real MCP server (in-memory transport) against a
 * fake database seeded with known PII, exercise every tool and error path, and
 * assert that no raw sensitive value appears in ANY response or audit record.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadConfig } from "../dist/config.js";
import { createServer } from "../dist/server.js";
import { AuditLogger } from "../dist/audit.js";

const RAW_PII = [
  "Ravi Kumar", "RAVI KUMAR", "ravi@example.com", "9876543210", "ABCPK1234F", "2341 2341 2346",
  "HDFC0001234", "ravi.k@okhdfc", "27ABCPK1234F1Z5", "123456789012345", "LN00012345", "s3cr3t-hash",
  "CUST-RK-001", "Flat 4, MG Road", "411001", "1990-05-17", "10.1.2.3",
];

const NOTES =
  "UPI ravi.k@okhdfc, A/C no 123456789012345, GSTIN 27ABCPK1234F1Z5, IFSC HDFC0001234, aadhaar 2341 2341 2346, loan LN00012345, ip 10.1.2.3";

const customers = {
  columns: [
    { name: "id", originalName: "id", table: "customers" },
    { name: "full_name", originalName: "full_name", table: "customers" },
    { name: "contact", originalName: "email", table: "customers" }, // aliased
    { name: "mobile_no", originalName: "mobile_no", table: "customers" },
    { name: "pan_no", originalName: "pan_no", table: "customers" },
    { name: "customer_ref", originalName: "customer_ref", table: "customers" }, // policy-only sensitive
    { name: "address", originalName: "address", table: "customers" },
    { name: "pincode", originalName: "pincode", table: "customers" },
    { name: "dob", originalName: "dob", table: "customers" },
    { name: "city", originalName: "city", table: "customers" },
    { name: "notes", originalName: "notes", table: "customers" },
    { name: "profile", originalName: "profile", table: "customers" },
  ],
  rows: [
    [
      1, "Ravi Kumar", "ravi@example.com", "9876543210", "ABCPK1234F", "CUST-RK-001", "Flat 4, MG Road", "411001",
      new Date("1990-05-17"), "Pune", NOTES, { email: "ravi@example.com", full_name: "Ravi Kumar", tags: ["9876543210"] },
    ],
  ],
};

const fakeDb = {
  kind: "postgres",
  async query(sql) {
    const s = sql.toLowerCase();
    if (s.includes("id = 999")) throw new Error("Duplicate entry 'Ravi Kumar' for key 'customers.full_name'");
    if (s.includes("id = 998")) {
      throw new Error('duplicate key value violates unique constraint "c_email_key"\nDETAIL: Key (email)=(ravi@example.com) already exists.');
    }
    if (s.includes("id = 997")) throw new Error('invalid input syntax for type integer: "ABCPK1234F"');
    if (s.includes("upper(full_name)")) {
      // Expression output: driver gives NO origin metadata — only the AST can tell.
      return { columns: [{ name: "nm" }, { name: "city" }], rows: [["RAVI KUMAR", "Pune"]] };
    }
    if (s.includes("from (select customer_ref as r")) {
      return { columns: [{ name: "r" }], rows: [["CUST-RK-001"]] };
    }
    if (s.includes("from users")) {
      return { columns: [{ name: "id", originalName: "id", table: "users" }, { name: "password_hash", originalName: "password_hash", table: "users" }], rows: [[1, "s3cr3t-hash"]] };
    }
    return customers;
  },
  async listTables() {
    return [
      { schema: "public", name: "customers", type: "BASE TABLE" },
      { schema: "public", name: "users", type: "BASE TABLE" },
      { schema: "public", name: "salaries", type: "BASE TABLE" },
    ];
  },
  async describeTable() {
    return [
      { name: "id", dataType: "integer", nullable: false },
      { name: "customer_ref", dataType: "text", nullable: true, default: "'CUST-RK-001'::text" },
      { name: "pan_no", dataType: "text", nullable: true },
      { name: "city", dataType: "text", nullable: true, default: "ravi@example.com" },
    ];
  },
  async close() {},
};

const env = {
  DATABASE_URL: "postgres://u:p@localhost:5432/customer_db",
  AUDIT_ENVIRONMENT: "test",
  AUDIT_ACTOR: "regression-suite",
  PII_BLOCKED_COLUMNS: "password_hash",
  PII_POLICY: JSON.stringify({
    allowed_tables: ["customers", "users"],
    tables: {
      customers: {
        sensitive_columns: ["full_name", "pan_no", "mobile_no", "email", "customer_ref"],
        allow_filtering: false,
        allow_joining: false,
        allow_grouping: false,
        allow_sorting: false,
      },
    },
    custom_patterns: [{ name: "LOAN_ID", pattern: "\\bLN\\d{8}\\b" }],
  }),
};

test("no sensitive value escapes through any response path or the audit log", async () => {
  const cfg = loadConfig(env);
  const auditLines = [];
  const audit = new AuditLogger(cfg.audit, (l) => auditLines.push(l));
  const server = createServer(cfg, async () => fakeDb, audit);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "regression", version: "1" });
  await client.connect(ct);

  const outputs = [];
  const call = async (name, args) => {
    const r = await client.callTool({ name, arguments: args });
    const text = r.content.map((c) => c.text).join("\n");
    outputs.push({ name, args, text, isError: !!r.isError });
    return { text, isError: !!r.isError };
  };

  // Happy paths
  const q1 = await call("query", { sql: "SELECT id, full_name, email AS contact, mobile_no, pan_no, customer_ref, address, pincode, dob, city, notes, profile FROM customers" });
  assert.equal(q1.isError, false, q1.text);
  assert.match(q1.text, /Pune/, "non-PII data still flows");
  assert.match(q1.text, /<LOAN_ID_/);
  const q2 = await call("query", { sql: "SELECT upper(full_name) AS nm, city FROM customers" });
  assert.equal(q2.isError, false, q2.text);
  assert.match(q2.text, /<NAME_/);
  const q3 = await call("query", { sql: "SELECT t.r FROM (SELECT customer_ref AS r FROM customers) t" });
  assert.equal(q3.isError, false, q3.text);
  await call("query", { sql: "SELECT * FROM customers WHERE id = $1", params: ["ravi@example.com"] });
  await call("list_tables", {});
  await call("describe_table", { table: "customers" });
  await call("pii_scan", { table: "customers" });

  // Blocked paths (literals in the SQL must not be echoed back)
  for (const sql of [
    "SELECT id FROM customers WHERE pan_no = 'ABCPK1234F'",
    "SELECT c.id FROM customers c JOIN loans l ON c.pan_no = l.pan",
    "SELECT id FROM customers WHERE full_name LIKE 'Ravi Kumar%'",
    "SELECT * FROM salaries WHERE note = 'Ravi Kumar'",
    "SELECT id, password_hash FROM users",
    "SELECT * FROM users",
    "DELETE FROM customers WHERE full_name = 'Ravi Kumar'",
    "SELECT 1; SELECT 'ravi@example.com'",
  ]) {
    const r = await call("query", { sql });
    assert.equal(r.isError, true, `should be blocked: ${sql}\n${r.text}`);
  }
  assert.equal((await call("describe_table", { table: "salaries" })).isError, true);
  assert.equal((await call("pii_scan", { table: "salaries" })).isError, true);

  // DB error paths
  for (const id of [999, 998, 997]) {
    const r = await call("query", { sql: `SELECT id FROM customers WHERE id = ${id}` });
    assert.equal(r.isError, true);
  }

  // list_tables honours the allowlist
  const lt = outputs.find((o) => o.name === "list_tables").text;
  assert.ok(!lt.includes("salaries"), lt);

  await client.close();

  // THE invariant
  const everything = [...outputs.map((o) => o.text), ...auditLines].join("\n").toLowerCase();
  for (const raw of RAW_PII) {
    assert.ok(!everything.includes(raw.toLowerCase()), `raw PII leaked: "${raw}"`);
  }

  // Audit sanity
  const recs = auditLines.map((l) => JSON.parse(l));
  assert.equal(recs.length, outputs.length);
  assert.ok(recs.every((r) => r.raw_pii_logged === false));
  assert.ok(recs.some((r) => r.decision === "BLOCKED"));
  assert.ok(recs.some((r) => r.decision === "ERROR"));
  const ok1 = recs.find((r) => r.tool === "query" && r.decision === "ALLOWED");
  assert.equal(ok1.actor, "regression-suite");
  assert.equal(ok1.environment, "test");
  assert.equal(ok1.database, "customer_db");
  assert.equal(ok1.rows_returned, 1);
  assert.ok(ok1.pii_detected > 0);
});

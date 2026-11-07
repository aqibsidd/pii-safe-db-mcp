import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyColumn, defaultPiiOptions, scrubText, sanitiseValue } from "../dist/pii.js";
import { sanitiseResult } from "../dist/sanitize.js";
import { assertReadOnly, assertNoBlockedColumns } from "../dist/sqlGuard.js";

const opts = defaultPiiOptions({ secret: "test-secret" });

test("classifies PII columns by name (snake, camel, aliases)", () => {
  assert.equal(classifyColumn(["email"], undefined, opts), "EMAIL");
  assert.equal(classifyColumn(["customerEmail"], undefined, opts), "EMAIL");
  assert.equal(classifyColumn(["mobile_no"], undefined, opts), "PHONE");
  assert.equal(classifyColumn(["first_name"], undefined, opts), "NAME");
  assert.equal(classifyColumn(["aadhar_number"], undefined, opts), "AADHAAR");
  assert.equal(classifyColumn(["pan_no"], undefined, opts), "PAN");
  assert.equal(classifyColumn(["password_hash"], undefined, opts), "SECRET");
  assert.equal(classifyColumn(["dob"], undefined, opts), "DOB");
  assert.equal(classifyColumn(["status"], undefined, opts), null);
  assert.equal(classifyColumn(["product_name"], undefined, opts), null);
  assert.equal(classifyColumn(["company"], undefined, opts), null);
  // alias hides the column, original name still caught
  assert.equal(classifyColumn(["x", "email"], "users", opts), "EMAIL");
});

test("allow / extra column overrides", () => {
  const o = defaultPiiOptions({ allowColumns: new Set(["users.name"]), extraColumns: new Set(["notes.body"]) });
  assert.equal(classifyColumn(["name"], "users", o), null);
  assert.equal(classifyColumn(["name"], "customers", o), "NAME");
  assert.equal(classifyColumn(["body"], "notes", o), "SECRET");
});

test("scrubs PII embedded in free text", () => {
  const s = scrubText(
    "Call Ravi at +91 98765 43210 or ravi.k@example.com, PAN ABCPK1234F, card 4111 1111 1111 1111, ip 10.0.0.12",
    opts,
  );
  assert.ok(!s.includes("98765"), s);
  assert.ok(!s.includes("example.com"), s);
  assert.ok(!s.includes("ABCPK1234F"), s);
  assert.ok(!s.includes("4111"), s);
  assert.ok(!s.includes("10.0.0.12"), s);
  assert.match(s, /<EMAIL_[0-9a-f]{10}>/);
});

test("does not mangle ordinary numbers and dates", () => {
  const s = "Order 12345 for 2024-05-01 total 1999.50, qty 3";
  assert.equal(scrubText(s, opts), s);
  assert.equal(sanitiseValue(42, null, opts), 42);
  assert.equal(sanitiseValue(1999.5, null, opts), 1999.5);
});

test("detects bare Indian mobile numbers stored as integers", () => {
  const v = sanitiseValue(9876543210, null, opts);
  assert.match(String(v), /PHONE/);
});

test("Aadhaar uses Verhoeff checksum (valid caught, random 12 digits ignored)", () => {
  // 2341 2341 2346 is a Verhoeff-valid sample number
  assert.match(scrubText("aadhaar 2341 2341 2346", opts), /AADHAAR/);
  assert.equal(scrubText("ref 2341 2341 2345", opts), "ref 2341 2341 2345");
});

test("token mode is deterministic, partial mode reveals little", () => {
  assert.equal(sanitiseValue("a@b.com", "EMAIL", opts), sanitiseValue("a@b.com", "EMAIL", opts));
  assert.notEqual(sanitiseValue("a@b.com", "EMAIL", opts), sanitiseValue("c@b.com", "EMAIL", opts));
  const p = defaultPiiOptions({ mode: "partial" });
  assert.equal(sanitiseValue("john@acme.io", "EMAIL", p), "j***@***.io");
  assert.equal(sanitiseValue("9876543210", "PHONE", p), "******3210");
  assert.equal(sanitiseValue("hunter2", "SECRET", p), "[SECRET]");
});

test("masks nested JSON by key and value", () => {
  const v = sanitiseValue({ profile: { email: "x@y.com", city: "Pune" }, note: "ping 9876543210" }, null, opts);
  assert.match(v.profile.email, /EMAIL/);
  assert.equal(v.profile.city, "Pune");
  assert.match(v.note, /PHONE/);
});

test("sanitiseResult masks aliased columns using original column metadata", () => {
  const r = sanitiseResult(
    {
      columns: [
        { name: "id" },
        { name: "contact", originalName: "email", table: "users" },
        { name: "city" },
      ],
      rows: [
        [1, "a@b.com", "Delhi"],
        [2, "c@d.com", "Mumbai"],
      ],
    },
    opts,
    1,
  );
  assert.equal(r.rows.length, 1);
  assert.equal(r.truncated, true);
  assert.equal(r.maskedColumns.contact, "EMAIL");
  assert.match(r.rows[0].contact, /EMAIL/);
  assert.equal(r.rows[0].city, "Delhi");
});

test("SQL guard allows reads", () => {
  for (const q of [
    "SELECT * FROM users",
    "  select id from users where note = 'drop table x';",
    "WITH a AS (SELECT 1) SELECT * FROM a",
    "SHOW TABLES",
    "DESCRIBE users",
    "EXPLAIN SELECT 1",
    "SELECT REPLACE(comment, 'a', 'b') AS start FROM posts",
    "(SELECT 1) UNION (SELECT 2)",
  ]) {
    assert.doesNotThrow(() => assertReadOnly(q), q);
  }
});

test("SQL guard blocks writes and tricks", () => {
  for (const q of [
    "DELETE FROM users",
    "UPDATE users SET email='x'",
    "SELECT 1; DROP TABLE users",
    "SELECT * INTO new_table FROM users",
    "SELECT * FROM users INTO OUTFILE '/tmp/x'",
    "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT LOAD_FILE('/etc/passwd')",
    "SELECT /*! 1; DROP TABLE users */ 1",
    "SELECT * FROM users FOR UPDATE",
    "SELECT sleep(100)",
    "TRUNCATE users",
    "",
  ]) {
    assert.throws(() => assertReadOnly(q), q);
  }
});

test("blocked columns cannot be referenced", () => {
  const blocked = new Set(["password_hash"]);
  assert.throws(() => assertNoBlockedColumns("SELECT password_hash FROM users", blocked));
  assert.throws(() => assertNoBlockedColumns('SELECT "password_hash" FROM users', blocked));
  assert.doesNotThrow(() => assertNoBlockedColumns("SELECT 'password_hash' AS label", blocked));
});

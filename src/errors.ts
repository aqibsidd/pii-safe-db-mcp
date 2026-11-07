import { scrubText, type PiiOptions } from "./pii.js";

/** Words after which a quoted token is an identifier (safe to keep), not a data value. */
const IDENT_CONTEXT =
  /\b(column|relation|table|schema|database|function|type|operator|constraint|index|sequence|view|role|key|field|alias|extension)\s*$/i;

/**
 * Remove data values from a database error message.
 *
 * DB errors routinely echo values: `Duplicate entry 'Ravi Kumar' for key`,
 * `invalid input syntax for type integer: "ABCPK1234F"`,
 * `Key (email)=(ravi@x.com) already exists`. Names are not detectable by
 * pattern, so every quoted literal is dropped unless it is clearly an identifier.
 */
export function sanitiseErrorMessage(message: string, opts: PiiOptions): string {
  let out = message.split("\n")[0].slice(0, 500);
  // Postgres key detail: Key (col)=(value)
  out = out.replace(/=\(([^)]*)\)/g, "=(?)");
  out = out.replace(/(['"`])((?:\\.|(?!\1).)*)\1/g, (m, q: string, _inner: string, offset: number, whole: string) => {
    const before = whole.slice(Math.max(0, offset - 30), offset);
    return IDENT_CONTEXT.test(before) ? m : `${q}?${q}`;
  });
  return scrubText(out, opts);
}

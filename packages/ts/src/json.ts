/**
 * Strict wire JSON: nonnegative safe integers, strings, booleans, null,
 * arrays, objects with unique keys. Canonical bytes follow the wire profile
 * (sorted keys, no whitespace, shortest escapes) matching trellis-core's
 * canonicalizer byte-for-byte for the permitted subset.
 */

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export class JsonError extends Error {
  constructor(public kind: string, msg: string) {
    super(msg);
  }
}

/** Strict parse: duplicate keys, unsafe numbers, and non-object leaves fail. */
export function parseStrict(text: string): Json {
  // Token-level checks run first so protocol violations (dup keys, unsafe
  // numbers) report their wire error rather than a generic SyntaxError.
  assertNoDupes(text);
  const v = JSON.parse(text);
  checkNumbers(v);
  return v as Json;
}

function checkNumbers(v: unknown): void {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0 || Object.is(v, -0)) {
      throw new JsonError("NON_SAFE_NUMBER", "number is not a safe nonnegative integer");
    }
    return;
  }
  if (Array.isArray(v)) {
    for (const x of v) checkNumbers(x);
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const x of Object.values(v as object)) checkNumbers(x);
  }
}

/** Detect duplicate object keys without trusting JSON.parse's last-wins. */
function assertNoDupes(text: string): void {
  // Tokenize minimally: track string keys immediately followed by ':' inside
  // object frames.
  const stack: Set<string>[] = [];
  let i = 0;
  const n = text.length;
  const isDigit = (c: string) => c >= "0" && c <= "9";
  while (i < n) {
    const c = text[i]!;
    if (c === '"') {
      const [s, ni] = scanString(text, i);
      i = ni;
      // key if next non-space char is ':'
      let j = i;
      while (j < n && (text[j] === " " || text[j] === "\t" || text[j] === "\n" || text[j] === "\r")) j++;
      if (text[j] === ":") {
        const top = stack[stack.length - 1];
        if (top) {
          if (top.has(s)) throw new JsonError("DUPLICATE_KEY", `duplicate key ${s}`);
          top.add(s);
        }
        i = j + 1;
      }
    } else if (c === "{") {
      stack.push(new Set());
      i++;
    } else if (c === "}") {
      stack.pop();
      i++;
    } else if (c === "-" || isDigit(c)) {
      // number token: must be a safe nonnegative integer
      const m = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
      if (m) {
        const t = m[0];
        if (t[0] === "-" || t.includes(".") || t.includes("e") || t.includes("E")) {
          throw new JsonError("NON_SAFE_NUMBER", `number ${t} not a safe nonnegative integer`);
        }
        if (t.length > 1 && t[0] === "0") {
          throw new JsonError("NON_SAFE_NUMBER", "leading zero");
        }
        i += t.length;
      } else {
        i++;
      }
    } else {
      i++;
    }
  }
}

function scanString(text: string, start: number): [string, number] {
  let i = start + 1;
  const n = text.length;
  let out = "";
  while (i < n) {
    const c = text[i]!;
    if (c === '"') return [out, i + 1];
    if (c === "\\") {
      const e = text[i + 1];
      switch (e) {
        case '"': out += '"'; i += 2; break;
        case "\\": out += "\\"; i += 2; break;
        case "/": out += "/"; i += 2; break;
        case "b": out += "\b"; i += 2; break;
        case "f": out += "\f"; i += 2; break;
        case "n": out += "\n"; i += 2; break;
        case "r": out += "\r"; i += 2; break;
        case "t": out += "\t"; i += 2; break;
        case "u": {
          const hex = text.slice(i + 2, i + 6);
          const cp = parseInt(hex, 16);
          if (!Number.isFinite(cp)) throw new JsonError("INVALID_ESCAPE", "bad \\u");
          out += String.fromCharCode(cp);
          i += 6;
          break;
        }
        default:
          throw new JsonError("INVALID_ESCAPE", `bad escape \\${e}`);
      }
    } else {
      out += c;
      i++;
    }
  }
  throw new JsonError("UNEXPECTED_EOF", "unterminated string");
}

const ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

function escStr(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cc = ch.codePointAt(0)!;
    const rep = ESCAPES[ch];
    if (rep !== undefined) {
      out += rep;
    } else if (cc < 0x20) {
      out += "\\u" + cc.toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

/** Canonical bytes: the exact wire encoding trellis-core produces. */
export function canonical(v: Json): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0 || Object.is(v, -0)) {
      throw new JsonError("NON_SAFE_NUMBER", "number is not a safe nonnegative integer");
    }
    return String(v);
  }
  if (typeof v === "string") return escStr(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map((k) => escStr(k) + ":" + canonical(v[k]!)).join(",") + "}";
}

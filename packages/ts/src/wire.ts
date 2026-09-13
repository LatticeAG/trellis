/** Wire framing + error model shared by the CLI and SDK. */

import { canonical, parseStrict, type Json } from "./json.js";

export const REQ_MAX = 65536;
export const RESP_MAX = 1048576;
export const DEFAULT_SOCKET = "/run/trellis/control.sock";

export type Code =
  | "INVALID_INPUT" | "UNKNOWN_FIELD" | "UNSUPPORTED_VERSION" | "UNSUPPORTED_HOST"
  | "UNAUTHORIZED" | "NOT_FOUND" | "CONFLICT" | "STALE_EPOCH" | "BUSY" | "STOPPED"
  | "CHALLENGE_USED" | "CHALLENGE_EXPIRED" | "CHALLENGE_INVALID" | "SCOPE_MISMATCH"
  | "SIGNATURE_INVALID" | "UNTRUSTED_KEY" | "HASH_MISMATCH" | "CHAIN_INVALID"
  | "TRANSITION_INVALID" | "INCOMPLETE" | "UNCONFIRMED" | "AUDIT_FAULT"
  | "EGRESS_FAULT" | "INVENTORY_LOST" | "CAP_ADAPTER_UNAVAILABLE" | "OUTPUT_LIMIT"
  | "COUNTER_EXHAUSTED" | "RECOVERY_PIN_REQUIRED";

export class TrellisError extends Error {
  constructor(public code: Code, msg?: string) {
    super(msg ?? code);
  }
}

/** Exit-code map (spec §6.1). `verify` uses 76 for evidence failures. */
export function exitCode(code: Code, verifyMode = false): number {
  switch (code) {
    case "INVALID_INPUT":
    case "UNKNOWN_FIELD":
    case "UNSUPPORTED_VERSION":
      return verifyMode ? 76 : 64;
    case "UNSUPPORTED_HOST":
    case "SIGNATURE_INVALID":
    case "UNTRUSTED_KEY":
    case "CAP_ADAPTER_UNAVAILABLE":
    case "RECOVERY_PIN_REQUIRED":
      return verifyMode ? 76 : 65;
    case "UNAUTHORIZED":
      return 69;
    case "BUSY":
      return 75;
    default:
      return verifyMode ? 76 : 70;
  }
}

export function frame(v: Json): Buffer {
  const payload = Buffer.from(canonical(v), "utf8");
  if (payload.length > REQ_MAX) throw new TrellisError("OUTPUT_LIMIT");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(payload.length);
  return Buffer.concat([len, payload]);
}

/** Incremental frame decoder; returns null until a full frame arrives. */
export class Deframer {
  private buf = Buffer.alloc(0);
  push(chunk: Buffer): Json | null {
    this.buf = Buffer.concat([this.buf, chunk]);
    if (this.buf.length < 4) return null;
    const n = this.buf.readUInt32BE(0);
    if (n > RESP_MAX) throw new TrellisError("OUTPUT_LIMIT", "response frame over bound");
    if (this.buf.length < 4 + n) return null;
    const payload = this.buf.subarray(4, 4 + n).toString("utf8");
    this.buf = this.buf.subarray(4 + n);
    return parseStrict(payload);
  }
}

let reqCounter = 0;

export function requestId(): string {
  // trq_ + 21-char suffix; per-process counter is fine (server keys replay on
  // the id), but keep it random-looking via time+counter.
  reqCounter = (reqCounter + 1) % 21 ** 21;
  const t = Date.now().toString(36).padStart(10, "0");
  const c = reqCounter.toString(36).padStart(11, "0");
  return "trq_" + (t + c).slice(-21).padStart(21, "0");
}

export function envelope(method: string, params: Json, id?: string): Json {
  return { v: 1, id: id ?? requestId(), method, params };
}

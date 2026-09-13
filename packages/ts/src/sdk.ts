/**
 * @latticeag/trellis — SDK client for the local Trellis watchdog.
 *
 * The SDK is a client only: no safety decision is made here. Every call is
 * one framed canonical-JSON request on the root-owned control socket; the
 * daemon's reducer is the sole writer.
 */

import { connect, type Socket } from "node:net";
import { spawnSync } from "node:child_process";
import { Deframer, envelope, frame, TrellisError, DEFAULT_SOCKET, type Code } from "./wire.js";
import { canonical, type Json } from "./json.js";

export interface RunView {
  run_id: string;
  state: string;
  head: { seq: string; hash: string };
  gate: string;
  audit: string;
  empty_observed: boolean;
  stop_reason: string | null;
  [k: string]: Json;
}

export class Client {
  constructor(public socketPath: string = DEFAULT_SOCKET) {}

  /** One request → one response. Connection is per-call; the run is
   *  daemon-owned, never client-lifetime-owned. */
  call(method: string, params: Json): Promise<Json> {
    const req = envelope(method, params);
    return new Promise((resolve, reject) => {
      const sock = connect(this.socketPath);
      const deframer = new Deframer();
      sock.once("error", () => reject(new TrellisError("UNAUTHORIZED", "control socket unavailable")));
      sock.on("connect", () => sock.write(frame(req)));
      sock.on("data", (chunk) => {
        const resp = deframer.push(chunk);
        if (resp === null) return;
        sock.end();
        const ok = (resp as Record<string, Json>).ok;
        if (ok === true) {
          resolve((resp as Record<string, Json>).result!);
        } else {
          const err = (resp as Record<string, Json>).error as Record<string, Json> | undefined;
          reject(new TrellisError((err?.code as Code) ?? "INVALID_INPUT"));
        }
      });
    });
  }

  hostGet(): Promise<Json> {
    return this.call("host.get", {});
  }
  runGet(runId: string): Promise<Json> {
    return this.call("run.get", { run_id: runId });
  }
  runList(after?: string, limit = 32): Promise<Json> {
    // `after` is a required field; the wire value for "from the start" is null.
    return this.call("run.list", { after: after ?? null, limit });
  }
  runStart(params: Json): Promise<Json> {
    return this.call("run.start", params);
  }
  runStop(runId: string, reason: "OPERATOR" | "POLICY_TRIP", noteHash: string | null): Promise<Json> {
    return this.call("run.stop", { run_id: runId, reason, note_hash: noteHash });
  }
  inventoryGet(runId: string): Promise<Json> {
    return this.call("inventory.get", { run_id: runId });
  }
  eventsRead(runId: string, afterSeq: string, through: Json, limit: number): Promise<Json> {
    return this.call("events.read", { run_id: runId, after_seq: afterSeq, through, limit });
  }
  certificateGet(runId: string): Promise<Json> {
    return this.call("certificate.get", { run_id: runId });
  }
}

/**
 * Agent-side heartbeat driver. Retains request IDs across uncertain retries;
 * never remints a consumed challenge; stops cleanly on terminal errors.
 * This object does NOT keep a hidden autonomous heartbeat alive once
 * `close()` is called or the channel errors out.
 */
export class HeartbeatChannel {
  private outstanding: Json | null = null;
  private closed = false;
  constructor(private sock: Socket) {}

  /** The run's challenge surface arrives as the first daemon packet. */
  static connect(socketPath: string, runId: string, bootId: string): Promise<HeartbeatChannel> {
    return new Promise((resolve, reject) => {
      const sock = connect(socketPath);
      sock.once("error", reject);
      sock.on("connect", () => resolve(new HeartbeatChannel(sock)));
      void runId;
      void bootId;
    });
  }

  async challenge(): Promise<Json> {
    const r = await this.rpc("agent.challenge", {});
    this.outstanding = r;
    return r;
  }

  /** One beat bound to the outstanding challenge. Retries reuse the same
   *  request ID and body — the daemon replays the stored response. */
  async beat(fields: {
    run_id: string;
    boot_id: string;
    scope_ok: boolean;
    claimed_processes: number;
    progress: string;
  }, requestId?: string): Promise<Json> {
    if (this.closed) throw new TrellisError("STOPPED", "channel closed");
    const ch = this.outstanding as Record<string, Json> | null;
    if (!ch) throw new TrellisError("CHALLENGE_INVALID", "no outstanding challenge");
    const params: Json = {
      run_id: fields.run_id,
      boot_id: fields.boot_id,
      challenge_id: ch.challenge_id!,
      seq: ch.seq!,
      nonce: ch.nonce!,
      policy_hash: ch.policy_hash!,
      scope_ok: fields.scope_ok,
      claimed_processes: fields.claimed_processes,
      progress: fields.progress,
    };
    const r = (await this.rpc("agent.beat", params, requestId)) as Record<string, Json>;
    this.outstanding = r.next ?? null;
    return r;
  }

  private rpc(method: string, params: Json, id?: string): Promise<Json> {
    const req = envelope(method, params, id);
    return new Promise((resolve, reject) => {
      const deframer = new Deframer();
      const onData = (chunk: Buffer) => {
        const resp = deframer.push(chunk);
        if (resp === null) return;
        this.sock.off("data", onData);
        const ok = (resp as Record<string, Json>).ok;
        if (ok === true) resolve((resp as Record<string, Json>).result!);
        else {
          const err = (resp as Record<string, Json>).error as Record<string, Json> | undefined;
          const code = (err?.code as Code) ?? "INVALID_INPUT";
          if (code === "STOPPED" || code === "CHALLENGE_INVALID") this.closed = true;
          reject(new TrellisError(code));
        }
      };
      this.sock.on("data", onData);
      this.sock.write(frame(req));
    });
  }

  close(): void {
    this.closed = true;
    this.sock.end();
  }
}

/** Locate the trellis-ctl helper (same install tree as the CLI). */
export function ctlPath(): string {
  return process.env.TRELLIS_CTL ?? "trellis-ctl";
}

/** Offline bundle verification via trellis-ctl — Rust owns the checks. */
export function verifyBundle(input: string, opts: {
  logPins: string[];
  policyPins: string[];
  head?: string;
  allowPrefix?: boolean;
}): { ok: true; result: Json } | { ok: false; code: Code; exit: number } {
  const args = ["verify", "--input", input];
  for (const p of opts.logPins) args.push("--log-pin", p);
  for (const p of opts.policyPins) args.push("--policy-pin", p);
  if (opts.head) args.push("--head", opts.head);
  if (opts.allowPrefix) args.push("--allow-prefix");
  const r = spawnSync(ctlPath(), args, { encoding: "utf8" });
  if (r.error) return { ok: false, code: "UNAUTHORIZED", exit: 69 };
  const text = (r.stdout ?? "").trim();
  const parsed = text ? (parseJsonLoose(text) as Record<string, Json>) : {};
  if (r.status === 0) return { ok: true, result: parsed };
  const code = ((parsed.error as Record<string, Json> | undefined)?.code as Code) ?? "INVALID_INPUT";
  return { ok: false, code, exit: r.status ?? 76 };
}

function parseJsonLoose(t: string): Json {
  try {
    return JSON.parse(t) as Json;
  } catch {
    return {};
  }
}

export { canonical };

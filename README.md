# Trellis

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Protocol: trellis/1](https://img.shields.io/badge/protocol-trellis%2F1-black)]()
[![Profile: linux-single-process-v1](https://img.shields.io/badge/profile-linux--single--process--v1-black)]()

**A local watchdog, a kernel-enforced egress stop, bounded replication
checks, and verifiable intervention records.**

Trellis is the LatticeAG local-first runtime watchdog. It runs an agent
workload inside a deny-by-default boundary, heartbeats it on a fixed
schedule, and — when the workload stops answering, drifts out of scope, or
is told to stop — closes the egress gate, kills the owned cgroup, and
writes a signed, replayable evidence chain you can verify offline.

No cloud. No fleet console. No remote kill authority. The daemon is the
only writer of safety state; the SDKs are clients, never controllers.

## What it does

- **Isolated launch** — dedicated task UID, workspace lease, namespaces,
  cgroup v2, runtime image verified by raw SHA-256 before mount.
- **Kernel-enforced egress** — cgroup-SKB gate, deny-by-default; packets
  are accepted only while a live lease and generation match the signed
  policy's static IPv4-TCP endpoint set.
- **Bounded replication** — seccomp profile denies process creation
  (`fork`, `vfork`, process-shaped `clone`/`clone3`, `unshare`, `setns`,
  non-IPv4-TCP sockets, `io_uring`); periodic inventory asserts one
  workload TGID under the thread bound.
- **Heartbeat liveness** — minted challenges, BOOTTIME deadlines; a
  missed or out-of-scope beat latches the run into stop.
- **Verifiable evidence** — every transition is a domain-hashed,
  Ed25519-signed event in an append-only chain; checkpoints and kill
  certificates are independently verifiable offline.
- **Recovery** — SQLite journal, byte-identical request replay, expected-
  head pins, and a `doctor`/`recover`/`migrate` operator path. A daemon
  that cannot trust its state goes LOCKED, never silently forward.

## Safety authority

Rust owns every safety-relevant decision: the reducer, the cryptographic
chain, the gate and seccomp policy, the inventory predicate, and the
verifier. TypeScript and Python packages are transport clients only.

```
crates/
  trellis-core        reducer, schemas, crypto, gate, seccomp, store,
                      verifier, fixtures, conformance harness
  trellisd            root daemon: control socket, SO_PEERCRED, single
                      writer, owner lock, guard spawn
  trellis-guard       independent guard process: fd-3 seqpacket RPC,
                      lease renew/stop/release, emergency kill
  trellis-conformance all 81 numbered TV-T vectors, JSON report
packages/
  ts                  trellis CLI + TypeScript SDK (thin client)
  python              Python SDK (thin client)
```

## Install (self-host)

Requires the enforcement profile: Linux **x86_64**, kernel ≥ 6.1,
cgroup v2 with kill/freezer/pids/memory/cpu, seccomp, namespaces, and
cgroup-SKB BPF. Nested containers without these fail `UNSUPPORTED_HOST` —
there is no weaker fallback profile.

```sh
cargo build --release
sudo install -m755 target/release/trellisd /usr/local/bin/
sudo install -m755 target/release/trellis-guard /usr/local/bin/
sudo install -m755 target/release/trellis-ctl /usr/local/bin/
pnpm --dir packages/ts install && pnpm --dir packages/ts build
sudo install -m755 packages/ts/bin/trellis /usr/local/bin/trellis
```

### First-run workflow

```sh
# 1. Host config + log key (seed is written 0600, never printed)
sudo trellis keygen --key-id trk_<21chars> --directory /etc/trellis/keys
sudoedit /etc/trellis/host.json            # see examples below

# 2. Preflight diagnostics — exits 65 unless the host supports the profile
trellis doctor --config /etc/trellis/host.json --json

# 3. Foreground daemon (systemd unit recommended in production)
sudo trellis daemon --config /etc/trellis/host.json

# 4. Author + sign a policy, then run
trellis policy hash policy.json --json
trellis policy sign policy.json \
  --key-id trk_... --key-file /etc/trellis/keys/trk_....seed \
  --output policy.signed.json
sudo trellis run --policy policy.signed.json \
  --workspace /srv/trellis/work-a -- /usr/bin/my-agent

# 5. Inspect, export, verify
trellis status --json
trellis events <run-id> --json
trellis receipt export <run-id> --output run.bundle.json
trellis verify run.bundle.json --log-pin pin.json --policy-pin pin.json --json
```

A stopped run's kill certificate states exactly what was observed:
`gate_closed`, `empty_observed`, `evidence: local-software-observation`,
`external_effects: NOT_REVERSED`, `remote_replication: NOT_ATTESTED`.
Trellis never claims remote containment it did not perform.

## CLI surface

| Command | Purpose |
| --- | --- |
| `trellis daemon --config PATH` | Foreground service; no daemonization |
| `trellis doctor --config PATH` | Capability/permission checks; exit 65 unless ready |
| `trellis status [--run ID]` | Host or run view |
| `trellis list [--after ID] [--limit N]` | Run discovery (cursor, 1–32) |
| `trellis run --policy P --workspace W -- CMD...` | Admit a run |
| `trellis stop ID [--reason] [--wait-ms]` | Operator stop; exit 10 on confirmed stop |
| `trellis inventory ID` | Last bounded process observation |
| `trellis events ID [--after SEQ] [--follow]` | Signed event entries |
| `trellis receipt export ID --output PATH` | Export a verify-ready bundle |
| `trellis certificate ID [--output PATH]` | Kill certificate (STOPPED only) |
| `trellis verify PATH --log-pin --policy-pin` | Offline evidence verification; exit 76 on failure |
| `trellis policy hash PATH` | Domain-separated policy hash |
| `trellis policy sign PATH --key-id --key-file --output` | Sign a PolicyBody |
| `trellis config validate PATH --kind host\|policy` | Schema + signature lint |
| `trellis keygen --key-id --directory` | Create-exclusive seed+pin pair |
| `trellis recover --config --expected-heads` | Contain orphans, verify pins; never resumes |
| `trellis migrate --config --to 1 --expected-heads` | Verified no-op for v1 |
| `trellis version` | CLI/protocol/storage/reducer/profile versions |

Exit codes: `64` usage · `65` host/policy/signature/adapter · `69`
unauthorized or unavailable socket · `75` busy · `74` local I/O · `76`
evidence verification failure · `70` anything else · `10` confirmed stop ·
`130` SIGINT.

## Conformance

```sh
cargo run -p trellis-conformance -- --profile offline-v1 --vectors all
cargo run -p trellis-conformance -- --profile linux-single-process-v1 \
    --vectors all --isolated-netns
```

All 81 numbered `TV-T--*` vectors run in both profiles. The offline
profile checks the reference model and the full protocol/verifier surface.
Under `linux-single-process-v1`, mandatory containment vectors
(sandbox syscalls, packet-hook verdicts) require a certified host: on a
host that fails preflight they report `UNSUPPORTED_HOST(checks)` instead
of borrowing confidence from the model — per the spec, unsupported
mandatory containment vectors prohibit the enforcement-profile release.

## Security model — honest limits

- Evidence is **local software observation**. Hardware attestation and
  remote replication are `NOT_ATTESTED` by construction.
- Stop is best-effort kernel enforcement: cgroup kill, gate close, and
  inventory checks are recorded; a workload's completed external effects
  are never claimed reversed.
- Supply-chain trust comes from pinned keys, raw-SHA-256 image checks,
  and reproducible builds — not from a registry.

## Not included (and never faked)

Fleet enrollment, remote kill, hosted attestation, cloud control, and
LexWatt composition (`cap.mode=lexwatt`) are paid/hosted surfaces. The
SDKs expose them as typed stubs that raise `NotImplemented` /
`HostedUnsupportedError` with the spec reference. The daemon answers
`CAP_ADAPTER_UNAVAILABLE` before `RunCreated` when a LexWatt policy is
submitted without a separately certified adapter.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm --dir packages/ts typecheck && pnpm --dir packages/ts test
cd packages/python && python3 -m pytest tests -q
```

## License

MIT — see [LICENSE](LICENSE).

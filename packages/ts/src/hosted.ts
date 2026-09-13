/**
 * Hosted / paid / cloud surfaces — explicit unsupported interfaces.
 *
 * The OSS edition ships no fleet console, remote kill authority, hosted
 * attestation, or cloud control plane. These classes exist so that callers
 * get a precise, typed failure with a spec reference instead of fake working
 * behavior. Reference: TRELLIS_SPEC_EXTREME.md §11 (composition boundaries)
 * and the OSS/paid split table (B-1).
 */

export class HostedUnsupportedError extends Error {
  readonly code = "NOT_IMPLEMENTED";
  constructor(surface: string, specRef: string) {
    super(
      `${surface} is a hosted/paid surface and is not part of the Trellis OSS ` +
        `edition. See ${specRef}. No remote control path exists in this build.`,
    );
    this.name = "HostedUnsupportedError";
  }
}

/** Fleet console enrollment/management — deferred per spec §11. */
export class FleetConsole {
  enroll(): never {
    throw new HostedUnsupportedError("fleet enrollment", "TRELLIS_SPEC §11 (deferred: fleet/hardware)");
  }
  heartbeat(): never {
    throw new HostedUnsupportedError("fleet heartbeat", "TRELLIS_SPEC §11");
  }
  remoteKill(_runId: string): never {
    throw new HostedUnsupportedError(
      "remote kill authority",
      "TRELLIS_SPEC §11 — kill authority is local-only",
    );
  }
}

/** Cloud control plane — does not exist in OSS. */
export class CloudControl {
  sync(): never {
    throw new HostedUnsupportedError("cloud control sync", "TRELLIS_SPEC §11");
  }
}

/** Remote attestation anchoring (TPM/Nitro) — deferred; never fabricate. */
export class HostedAttestation {
  anchor(_head: unknown): never {
    throw new HostedUnsupportedError(
      "hosted attestation anchoring",
      "TRELLIS_SPEC §11.2 — operators may export checkpoints to their own storage",
    );
  }
}

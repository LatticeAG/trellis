"""Hosted / paid / cloud surfaces — explicit unsupported interfaces.

The OSS edition ships no fleet console, remote kill authority, hosted
attestation, or cloud control plane. These classes give callers a precise,
typed failure with a spec reference instead of fake working behavior.
Reference: TRELLIS_SPEC_EXTREME.md §11 (composition boundaries) and the
OSS/paid split table (B-1).
"""


class HostedUnsupportedError(NotImplementedError):
    """Raised by every hosted surface; carries the spec reference."""

    def __init__(self, surface: str, spec_ref: str):
        super().__init__(
            f"{surface} is a hosted/paid surface and is not part of the "
            f"Trellis OSS edition. See {spec_ref}. No remote control path "
            f"exists in this build."
        )
        self.surface = surface
        self.spec_ref = spec_ref


class FleetConsole:
    """Fleet console enrollment/management — deferred per spec §11."""

    def enroll(self):
        raise HostedUnsupportedError("fleet enrollment", "TRELLIS_SPEC §11")

    def heartbeat(self):
        raise HostedUnsupportedError("fleet heartbeat", "TRELLIS_SPEC §11")

    def remote_kill(self, run_id: str):
        raise HostedUnsupportedError(
            "remote kill authority", "TRELLIS_SPEC §11 — kill authority is local-only"
        )


class CloudControl:
    """Cloud control plane — does not exist in OSS."""

    def sync(self):
        raise HostedUnsupportedError("cloud control sync", "TRELLIS_SPEC §11")


class HostedAttestation:
    """Remote attestation anchoring (TPM/Nitro) — deferred; never fabricate."""

    def anchor(self, head):
        raise HostedUnsupportedError(
            "hosted attestation anchoring",
            "TRELLIS_SPEC §11.2 — operators may export checkpoints to their own storage",
        )

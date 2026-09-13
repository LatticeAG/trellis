"""trellis_sdk — Python client for the local Trellis watchdog.

The SDK is a client only: no safety decision is made here. Every call is one
framed canonical-JSON request on the root-owned control socket; the daemon's
reducer is the sole writer.
"""

from .client import Client, HeartbeatChannel, TrellisError
from .canon import canonical_bytes, parse_strict
from .hosted import FleetConsole, CloudControl, HostedAttestation, HostedUnsupportedError

__all__ = [
    "Client",
    "HeartbeatChannel",
    "TrellisError",
    "canonical_bytes",
    "parse_strict",
    "FleetConsole",
    "CloudControl",
    "HostedAttestation",
    "HostedUnsupportedError",
]

__version__ = "1.0.0"

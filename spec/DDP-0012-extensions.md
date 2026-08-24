# DDP-0012 Extensions

**Status:** Accepted (DDP/2)

Extensions MAY introduce object types, routing metadata, receipt kinds, capabilities, or applications. Core DDP MUST remain payload-agnostic.

## Encoding

Each extension: `{ name, critical, data }`. Maximum count: `MAX_EXTENSIONS` (32). Oversized sets MUST be rejected (DDP1006).

## Unknown extensions

| Class | Behavior |
| --- | --- |
| optional (`critical=false`) | MAY preserve and forward; MUST NOT fail the session |
| critical (`critical=true`) | MUST reject the object or handshake (DDP1003) |

## Application namespaces

Examples (not exhaustive): `dd.chat`, `dd.file`, `dd.git`, `dd.package`, `dd.web`, `dd.sensor`, `dd.receipt`, `dd.identity-transition`.

Topics (`dd.topic/…`) are OPTIONAL routing hints. Nodes MUST NOT accept unlimited unsolicited topic storage; opt-in and quotas apply.

Public Drops are signed and integrity-checked. Public does **not** mean “trust everything received.”

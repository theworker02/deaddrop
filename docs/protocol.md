# Protocol

DeadDrop Protocol is specified in [`/spec`](../spec/DDP-0000-overview.md) (DDP-0000 … DDP-0015).

Wire version **DDP/2**. Historical DDP/1 (`protocol/DDP-SPEC.md`) is archive only.

Session states: Disconnected → TransportConnected → Negotiating → Authenticated → InventorySync → Transferring → Idle → Closing.

Drop states: Created, Stored, Queued, Offered, PartiallyTransferred, Forwarded, Delivered, Expired, Rejected, GarbageCollected.

Errors are coded (`DDP1001_…`, `DDS2001_…`, …) with category and retryability.

Wireshark dissector and `.ddcap` capture format: PLANNED (document once the frame enum is frozen).

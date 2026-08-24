# DDP-0007 Routing

Routing decides “forward this Drop to this peer?”. It MUST NOT implement sockets.

Strategies: direct, epidemic, spray-and-wait, encounter, utility. Coefficients are policy, not constants frozen in the protocol.

Spray-and-wait: if remaining copies > 1, copy to eligible peers and decrement; if 1, wait for the destination.

Encounter/utility scores MUST be explainable (`dd route --explain`). Nodes MUST NOT export another person’s movement history. No GPS is REQUIRED.

# Architecture (v2.0)

```
                 APPLICATIONS
        CLI     examples     Git (PLANNED)
                 \    |    /
                  deaddrop-sdk
                       │
                 deaddrop-net
              routing / discovery / TCP / QUIC
              sync / scheduler / adaptive router
                       │
                 deaddrop-core
              protocol / crypto / identities
              chunks / store / receipts / spaces
```

Binaries live in `deaddrop-app`. Dependency direction is strict: app → sdk → net → core. Core never depends on net.

Store-carry-forward and object lifecycle: see DDP-0000.

# Extension identifier registry

Informational only. Not a network dependency.

| ID | Status |
| --- | --- |
| dd.message/1 | present (`dd msg`) |
| dd.space/1 | present |
| dd.board/1 | present |
| dd.channel/1 | present |
| dd.package/1 | present |
| dd.web/1 | pack only; viewer PLANNED |
| dd.git/1 | PLANNED |
| dd.receipt/1 | present |
| dd.identity-transition/1 | present |
| dd.revocation/1 | record file; SCF propagation is the Drop itself |

Third parties MAY use `com.example.*` / `org.*` without merging into this repository. Unknown **optional** extensions MUST be ignored; **critical** unknown extensions MUST fail (DDP-0012).

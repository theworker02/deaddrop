# DDP-0003 Discovery

`DiscoveryProvider` advertises reachability only.

LAN beacon (40 bytes): magic `DDP2` || version u16 BE || stream_port u16 BE || peer_id 32 bytes. Default UDP 7946.

Static peers and manual locators MUST be supported.

Bluetooth LE, Wi-Fi Direct, USB, NFC, WebRTC, internet rendezvous: PLANNED. Stubs MUST NOT claim they work.

Discovering `dd:XYZ` means: a device *claiming* that identity is reachable. Authentication is DDP-0004.

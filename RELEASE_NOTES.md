True Proxy 0.12.10

- TCP and UDP packets with an unknown owner wait up to three seconds for Windows to identify the process. When a process is identified, its routing rules apply. On timeout, queued packets go Direct.
- TCP keeps the Direct route for the connection. UDP can switch to the configured route when a later lookup identifies the owner.
- The attribution queue holds up to 64 flows, 16 packets per flow, and 2 MiB of packet data. Packets beyond these limits are dropped.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental. Tests use synthetic traffic and local sockets.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.12.10/docs/branding/slint-badge.png)](https://slint.dev)

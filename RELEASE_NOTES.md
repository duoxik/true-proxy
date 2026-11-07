True Proxy 0.11.2

- X-RAY Fallbacks suggests GeoIP and Geosite tags from the installed databases. Selected tags can be removed individually. Press Enter to add a custom tag.
- Tunnel DNS accepts `tcp://host:port` for DNS-over-TCP through VLESS, alongside IP addresses and HTTPS DoH URLs.
- Xray-core starts detached from the Windows console and retains its restricted privileges. This addresses a possible cause of startup error `0xC0000142`.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.11.2/docs/branding/slint-badge.png)](https://slint.dev)

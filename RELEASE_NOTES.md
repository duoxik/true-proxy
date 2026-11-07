True Proxy 0.11.0

- Settings → Modules installs the optional Windows x64 Xray-core from an official release and verifies its SHA-256. After installation, X-RAY appears as a group in the sidebar with a dashboard, update controls, and six configuration and monitoring sections.
- X-RAY supports VLESS RAW/TCP + TLS, including Vision. Profiles imports `vless://` links and HTTPS subscriptions containing links in text or Base64. Start Xray to expose a local SOCKS5 listener at `127.0.0.1:2081` by default.
- DNS configures resolvers for the tunnel. Add to hosts pins the VPN server address for Xray while preserving its TLS server name. Fallbacks supports configurable GeoIP and GeoSite sources, Direct tags, and periodic updates. The defaults use XTLS GeoIP Lite and GeoSite Standard with Russian tags.
- X-RAY Connections shows recent access events reported by the core. Logs has independent recording, level and source filters, clearing, and text copying. Access events indicate accepted or rejected requests.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental. Xray module checks cover verified downloads and local SOCKS startup and shutdown. End-to-end traffic through a remote VLESS server with WinDivert requires integration testing.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.11.0/docs/branding/slint-badge.png)](https://slint.dev)

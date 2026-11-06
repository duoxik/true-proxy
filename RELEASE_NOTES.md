True Proxy 0.9.0

- Dashboard shows transfer totals, live upload and download rates, and compact routing rows with switches for user rules.
- Proxies and Dashboard show latency and exit location after a manual check. Location comes from an HTTPS request to IPinfo through the selected SOCKS5 proxy.
- Connections opens in the main window with traffic totals, process search, and multi-select route and status menus. Start times use the Windows local clock.
- Network → Logs shows backend and connection events with level and source filters. Follow starts off.
- Routing Rules has search and compact rule cards. Local remains the first Direct rule and its CIDRs can be edited. A running engine applies saved changes after an explicit restart.

Existing profiles use the same default Local ranges. Custom Local CIDRs stay in the device profile when importing or exporting portable JSON. Restore the default ranges before opening a customized profile in v0.8.0.

Windows x64. WinDivert is bundled in the executable. Windows resolves DNS. The interception backend is experimental.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.9.0/docs/branding/slint-badge.png)](https://slint.dev)

True Proxy 0.10.0

- Connections shows current traffic when routing is active and observes system TCP connections when routing is paused. Paused rows show the route that the saved rules would select. Passive observation samples once a second and may miss short-lived sockets. UDP session details are available while routing is active.
- Connections remembers route and status selections. Reset restores Proxy, Connecting, Active and Closing and clears the process search. Each completed status starts recording from the moment it is selected. The ROUTE column shows proxied connections as `Proxy · name`.
- Network → Logs supports text selection and copying, Clear and a Start / Pause control that remembers its state. The buffer holds the latest 256 lines. Follow starts off.
- SOCKS checks run at startup and every 20 seconds. Dashboard and Proxies show latency or a red `-1 ms` when the check fails. Manual GeoIP results show the exit country flag next to the location. Check results appear inline.
- Saved routing changes show a Restart banner while routing is active. Dashboard links open Proxies and Rules directly. Rule rows are more compact, and fixed rules show disabled controls.

Windows x64. WinDivert is bundled in the executable. Windows resolves DNS. The interception backend is experimental.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.10.0/docs/branding/slint-badge.png)](https://slint.dev)

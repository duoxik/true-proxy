True Proxy 0.12.11

- Added ShadowNet subscription support for shadow-net.site and its subdomains. Import and Refresh send the same saved, DPAPI-protected device identity and Windows client metadata.
- Subscription device-limit and missing-HWID responses now show actionable errors. Device identities are restricted to the original HTTPS origin during redirects.
- Added import of independent VLESS RAW/TCP servers with TLS or REALITY from Xray JSON configurations and configuration arrays, preserving region names and existing credential protection. Input is bounded to 1 MiB and 128 nodes.
- General now follows the approved layout with a prominent Configuration card, smaller Appearance and Startup cards, and a compact Application updates section.
- Moved the version and Windows DNS information into the page footer. Removed the About and System DNS cards, the Icon licenses button, its popup and UI-only license state.

ShadowNet support was tested with synthetic subscription responses. A live device-bound subscription has not been checked. Balancers, proxy chains and other transports remain unsupported.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental. Checks ran without intercepting user traffic.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.12.11/docs/branding/slint-badge.png)](https://slint.dev)

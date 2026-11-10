True Proxy 0.12.9

- Settings now has General and Modules in the main sidebar. Configuration import/export is the fourth General card.
- General uses a two-column card grid, switching to a single column in narrow windows.
- Module versions appear beside their names. Text actions sit in the upper-right corner of shared cards; the redundant Open action for Xray-core was removed.
- Added Check for Updates for hpwnr, with a separate explicit installation action and verified Windows x64 release assets.
- Dashboard Proxy no longer nests cards or puts latency and location inside pills.
- GeoIP checks through SOCKS are limited to once every five minutes. A fallback handles provider rate limits, and temporary failures preserve the last known location.
- Local and Fallback switches remain enabled and locked, using a dark accent track. Enabled rule switches now have white thumbs.
- Removed the sidebar logo and added a divider below the native window title bar.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental; these changes were checked without intercepting user traffic.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.12.9/docs/branding/slint-badge.png)](https://slint.dev)

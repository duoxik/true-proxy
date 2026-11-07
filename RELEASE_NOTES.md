True Proxy 0.11.1

- X-RAY Profiles groups manually imported profiles and subscriptions separately. Each subscription has its own Refresh button.
- X-RAY DNS shows a read-only table of VPN server addresses. True Proxy resolves hostnames as profiles and subscriptions change or when you select Refresh. Xray connects to the saved IP and preserves the TLS server name.
- Settings → Modules hosts Xray-core update controls. The update check stays quiet when the installed version is current. Startup errors appear in X-RAY with the Windows exit code or core output when available.
- The sidebar has consistent spacing and collapsible groups. Main is now Proxy. Connections uses DPI-aware Windows app icons.
- Automatic proxy checks refresh the exit location, keeping the last known location when a lookup fails.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.11.1/docs/branding/slint-badge.png)](https://slint.dev)

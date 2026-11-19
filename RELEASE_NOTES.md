True Proxy 0.12.12

- Run several Xray profiles at once. Create local SOCKS5 ports in **X-RAY → Ports** and assign profiles in **Profiles**. Switching profiles affects only the selected port. Use **Restart** to apply the change.
- Add each local address to **Proxies** manually, then assign it to apps in **Rules**. Renaming a port keeps its profile bindings. If you change its number, update that address in Proxies.
- Ports shows which listeners are open and why a port could not open. If an active profile disappears during a subscription refresh, the subscription shows **Active profile removed** so you can choose its replacement.
- Profile port menus use the app's light and dark themes. Keyboard focus rings have been removed across the interface.

**Upgrading from 0.12.11.** Your existing Xray listener becomes the Default port and keeps its number. Profiles, subscriptions and the active profile are preserved. If you use custom Tunnel DNS, select an enabled profile in **X-RAY → DNS → DNS exits through** before starting Xray.

On first use, this version saves Xray settings in the named-port format. If you plan to return to 0.12.11, back up `%LOCALAPPDATA%\TrueProxy\xray\settings.json` before upgrading. The older version cannot read the new format.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental. Checks ran without intercepting user traffic.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.12.12/docs/branding/slint-badge.png)](https://slint.dev)

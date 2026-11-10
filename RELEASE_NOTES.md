True Proxy 0.12.8

- Unified the remaining pages and X-RAY sections with shared native components and embedded Lucide icons.
- Added hpwnr as a separate module in Settings → Modules. Encrypted imports now offer Install and Import instead of downloading it silently.
- Dashboard keeps a bounded two-minute traffic graph across tab changes, with a vertical speed scale. Sampling stops in hidden/minimized windows and expires after leaving Dashboard.
- Traffic scale labels sit at the card edge, with a compact column sized to their content.
- Dashboard latency shows successful results, including 0 ms, in green and failures as -1 ms in red; the Latency label stays gray.
- Built-in Local and Fallback rules show enabled, locked gray switches and use the shared card surface.
- Install and Restart now downloads, verifies and installs the update without requiring a manual routing pause. Saved routing state is restored on restart.
- Update installation waits for startup confirmation from the new UI and restores the previous EXE on a startup failure or timeout.
- Added an isolated local UI preview launcher, Test-Local.cmd. Local dev builds cannot install GitHub updates.

Windows x64. WinDivert is bundled in the executable. The interception backend is experimental; these changes were checked without intercepting user traffic.

[![Made with Slint](https://raw.githubusercontent.com/duoxik/true-proxy/v0.12.8/docs/branding/slint-badge.png)](https://slint.dev)

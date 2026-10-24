# Third-party components

True Proxy is built with Rust and the dependencies pinned in `Cargo.lock`.
The application has no license grant of its own unless the repository owner
adds one. Third-party licenses remain applicable independently.

## Slint 1.18.1

This application uses Slint (https://slint.dev), copyright SixtyFPS GmbH and
contributors. Slint is used under its royalty-free desktop license option.
The public README download page and release pages display the unmodified
Slint attribution badge, using section 2(b) of the Royalty-free License 2.0.
The badge is also included in docs/branding/slint-badge.png.

- Source: https://github.com/slint-ui/slint/tree/v1.18.1
- License options and full texts: https://github.com/slint-ui/slint/blob/v1.18.1/LICENSE.md
- Some bundled fonts, assets and dependencies have their own licenses; see
  the Slint repository's REUSE metadata and LICENSES directory.

## WinDivert 2.2.2

Copyright Basil and contributors. Distributed as a replaceable, dynamically
loaded DLL plus its signed driver, using the LGPLv3-or-later option offered
by upstream. The unmodified DLL, signed SYS and upstream license are embedded
in the EXE and extracted into the user's local runtime directory on demand.
A complete DLL/SYS pair placed alongside the EXE takes precedence, allowing
replacement with a compatible modified build. True Proxy does not include or
modify WinDivert kernel source. Keep the upstream license files alongside
the distributed binaries.

- Source and corresponding release: https://github.com/basil00/WinDivert/tree/v2.2.2
- Original binary archive: https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
- Archive SHA-256: `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`

## Rust dependencies

The package step produces `DEPENDENCIES.json` from Cargo's resolved metadata,
listing source repositories and declared license expressions. The list also
includes development and build dependencies; inclusion there does not imply
that a crate is embedded in the executable. Crate license/notice files are
copied into `licenses/` when packaging from a local Cargo registry.

## GNU runtime (GNU builds only)

GNU builds may include `libgcc_s_seh-1.dll` and `libwinpthread-1.dll` from the
matching MinGW-w64 toolchain. These DLLs must remain replaceable.

- GCC runtime: GPLv3 with GCC Runtime Library Exception 3.1.
  https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
  https://github.com/gcc-mirror/gcc/tree/releases/gcc-16.2.0
- winpthreads: upstream permissive license and notices.
  https://github.com/mingw-w64/mingw-w64/tree/v14.0.0/mingw-w64-libraries/winpthreads

Packaging copies the matching toolchain notices to `licenses/toolchain`.
MSVC builds do not use the GNU runtime DLLs.

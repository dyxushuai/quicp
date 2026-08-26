# Windows carrier

QUICP Tier 0 on Windows uses the WinDivert network-layer API. Winsock raw TCP is not used: the
WinDivert WFP/WDF provider diverts packets matching one `FakeTCP` four-tuple, drops malformed and
kernel-generated RST packets, and injects QUICP's TCP-shaped IPv4 packets in the selected direction.

## Runtime files and privileges

Ship the matching official WinDivert distribution beside the application:

```text
WinDivert.dll
WinDivert64.sys   # 64-bit process
# WinDivert32.sys # only for a 32-bit process
```

The checked Windows CI profile is `x86_64-pc-windows-msvc`; the 32-bit package is documented for
the matching process architecture but is not part of the release test matrix.

The official distribution's driver is signed. Do not commit these binaries to this repository or
replace them with an unsigned build. `WinDivertOpen` installs/opens the provider on demand and
requires an elevated Administrator process. A missing DLL, missing driver, invalid signature, or
insufficient privilege is returned as an endpoint-construction error; QUICP never falls back to
UDP or a host-only carrier.

The WinDivert package is LGPLv3. Preserve its license and notices in the application distribution.
See the [WinDivert documentation](https://reqrypt.org/windivert-doc.html) for the official binary
layout, signing, and redistribution requirements.

## Rust usage

Build the Tokio native carrier profile:

```powershell
cargo build --locked --features runtime-tokio
```

Use `Client::bind_fake_tcp` or `Server::bind_fake_tcp` with one or two IPv4 `FourTuple` values.
`packet_socket` remains in the shared configuration for Unix parity and is ignored by the Windows
adapter. The adapter is IPv4-only today; IPv6 support must add an explicit filter and packet-path
test before it is enabled.

## Native smoke test

The repository test validates that an elevated process can open a filtered WinDivert tuple:

```powershell
cargo test --locked --features runtime-tokio,internal-bench --test windows_windivert -- --ignored
```

This is only a provider/bind check. Release admission also needs a two-host or external-interface
packet capture proving SYN data, exact tuple filtering, RST suppression, payload delivery,
loss/reordering, multipath, and shutdown cleanup. Loopback is not sufficient for the inbound path:
WinDivert treats localhost traffic as outbound-only.

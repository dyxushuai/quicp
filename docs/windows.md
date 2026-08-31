# Windows carrier

QUICP Tier 0 on Windows uses the WinDivert network-layer API. Winsock raw TCP is not used: the
WinDivert WFP/WDF provider diverts packets matching one `FakeTCP` four-tuple, drops malformed and
kernel-generated RST packets, and injects QUICP's TCP-shaped IPv4 packets in the selected direction.

## Runtime files and privileges

QUICP admits only the x64 files from the official `WinDivert-2.2.2-A.zip` distribution beside the
application:

```text
WinDivert.dll
WinDivert64.sys
```

The adapter resolves `WinDivert.dll` from the canonical directory of the running executable and
loads that absolute path with `LOAD_LIBRARY_SEARCH_SYSTEM32`. It does not search the working
directory or `PATH`; dependencies may resolve only from System32.

Before loading, QUICP opens the application directory, DLL, and driver without following a final
reparse point; rejects writable ACLs or untrusted owners; verifies these SHA-256 values; and
verifies the driver's Authenticode signature:

```text
WinDivert-2.2.2-A.zip  63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
x64/WinDivert.dll     c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2
x64/WinDivert64.sys   8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2
```

The file handles remain locked for the carrier lifetime, and the loaded module identity must match
the verified DLL. A missing, redirected, modified, or differently-versioned binary fails endpoint
construction. Supporting another WinDivert release requires an explicit source/package review and
hash update. The checked Windows profile is x64; 32-bit processes fail closed.

The official distribution signs the driver, not the DLL. DLL identity therefore comes from the
pinned hash and protected installation boundary. Do not commit the binaries to this repository or
replace them with a locally built copy. `WinDivertOpen` installs/opens the provider on demand and
requires an elevated Administrator process. QUICP never falls back to UDP or a host-only carrier.

The WinDivert package is LGPLv3. Preserve its license and notices in the application distribution.
See the [WinDivert documentation](https://reqrypt.org/windivert-doc.html) for the official binary
layout, signing, and redistribution requirements.

## Rust usage

Build the Tokio native carrier profile, then install the executable and both WinDivert files into
an administrator-controlled directory. Do not run the elevated carrier from Cargo's user-writable
`target` directory. A packaging tool must set the directory and file owners to `SYSTEM`,
`Administrators`, or `TrustedInstaller`, and grant mutation rights only to those principals.

```powershell
cargo build --locked --features runtime-tokio
```

Use `Client::bind_fake_tcp` or `Server::bind_fake_tcp` with one or two IPv4 `FourTuple` values.
`packet_socket` remains in the shared configuration for Unix parity and is ignored by the Windows
adapter. The adapter is IPv4-only today; IPv6 support must add an explicit filter and packet-path
test before it is enabled.

## Native smoke test

After copying the test executable and the pinned WinDivert files into that protected directory, run
the test executable directly with this filter:

```powershell
quicp-<test-hash>.exe windivert_carrier_binds_a_filtered_tuple --ignored
```

This is only a provider/bind check. Release admission also needs a two-host or external-interface
packet capture proving SYN data, exact tuple filtering, RST suppression, payload delivery,
loss/reordering, multipath, and shutdown cleanup. Loopback is not sufficient for the inbound path:
WinDivert treats localhost traffic as outbound-only.

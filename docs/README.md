# QUICP documentation

## User-facing contract

The repository defines one QUICP wire profile: `quicp`. The package release number (`0.1.1`) is
the distribution version, not a second protocol identity.

- [Read the protocol and boundaries](protocol.md)
- [Production acceptance checklist](production-acceptance-checklist.md)
- [Use the SDK](../sdk/README.md)
- [Run the examples](../examples/README.md)
- [Run the benchmarks](../benches/README.md)

The [feature map](../README.md#feature-flags) lists each optional capability and its starting example.

## Architecture decisions

- [Carrier platform matrix](adr/0001-carrier-platform-matrix.md)
- [Datagram-first adaptive recovery](adr/0003-datagram-first-recovery.md)

## Background

- `research/` contains external protocol and backend investigations.

Research is background context, not a promise of interoperability or a supported platform profile.
The protocol document and the production checklist are the release contract.

# QUICP domain glossary

## Carrier

A carrier is the packet-level underlay that transports QUICP datagrams. It preserves the QUICP
datagram boundary and does not provide application ordering, peer authentication, or encryption.

## FakeTCP

FakeTCP is QUICP's TCP-shaped carrier format. It resembles TCP on the wire, but it is not a TCP
byte stream and must not be used as an ordered wrapper around QUICP.

## Path

A path is one carrier four-tuple. A multipath session may use more than one path while keeping its
QUICP session and flow state above those paths.

## Adapter

An adapter connects a carrier or host integration to a platform, runtime, or foreign-language
environment. The adapter owns platform handles and permissions; the protocol core owns QUICP state.

## Host-driven execution

Host-driven execution means the embedding host owns packet I/O and the monotonic clock. The host
advances bounded protocol work when I/O or timer readiness is available.

## Carrier tiers

- Tier 0 is a verified wire carrier intended for ISP-facing FakeTCP camouflage.
- Tier 1 is a virtual packet integration such as TUN/TAP and smoltcp.
- Tier 2 is a mobile packet integration such as Network Extension or `VpnService`.

Tier 1 and Tier 2 do not claim Tier 0 camouflage unless a separately verified wire carrier is
attached.

## Configuration extension

A configuration extension runs while transport options are assembled. It is not a packet callback,
data-plane hook, or foreign-language ABI.

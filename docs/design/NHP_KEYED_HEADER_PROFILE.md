# NHP keyed-header profile: conformance and rollout gate

Status: **design only; release blocked**

This document records the protocol decisions that must be made before LayerV
implements or advertises a keyed NHP header profile. It does not change the
wire format, enable a new version, or claim conformance with an unresolved
standard.

The durable session-control work remains on LayerV's deployed NHP 1.1
envelope. That envelope has a 240-byte Curve header, including the 80-byte IBC
identity field, and uses nanosecond timestamps. Its trailing 32-byte
`HeaderDigest` is an unkeyed hash of public header inputs; it does not cover the
payload ciphertext and is not an authenticator.

## Why this is a separate protocol change

The CSA *Stealth Mode SDP for Zero Trust Network Infrastructure* publication
currently contains two incompatible descriptions of the header:

- its prose says the fixed header is 160 bytes for the international suite and
  224 bytes for the domestic suite;
- its field table includes an 80-byte IBC identity field, which makes those
  totals impossible when all listed fields are present;
- the same table specifies a MAC derived from the Noise chaining key and
  covering the header plus payload ciphertext; and
- it defines the major version as the boundary for backward-incompatible
  changes.

The current OpenNHP reference implementation provides another observable
baseline:

- Curve is 240 bytes and GMSM is 304 bytes;
- both layouts include the 80-byte identity field; and
- the field named `HMAC` is produced with an ordinary hash seeded only with
  public constants and public header inputs. The payload ciphertext is not
  included.

Primary references:

- [CSA NHP publication](https://cloudsecurityalliance.org/artifacts/stealth-mode-sdp-for-zero-trust-network-infrastructure)
- [OpenNHP Curve header](https://github.com/OpenNHP/opennhp/blob/main/nhp/core/scheme/curve/header.go)
- [OpenNHP GMSM header](https://github.com/OpenNHP/opennhp/blob/main/nhp/core/scheme/gmsm/header.go)
- [OpenNHP header digest construction](https://github.com/OpenNHP/opennhp/blob/main/nhp/core/initiator.go)

Removing the identity field, changing the fixed header length, changing the
timestamp unit, deriving a new key, changing the authenticated transcript, or
covering payload ciphertext changes packet framing and cryptographic meaning.
Those changes cannot ship as NHP 1.2. They require NHP 2 or an explicitly
negotiated profile with an equally strong version boundary.

## Proposed security direction, not yet a frozen standard

The replacement integrity field should be a real keyed MAC:

1. derive a dedicated header-MAC key from the Noise chaining key after the
   handshake state needed by both peers is available;
2. use domain separation dedicated to this profile;
3. authenticate the complete serialized header except the MAC field itself;
4. authenticate the exact payload ciphertext bytes, including the body AEAD
   tag, and any protocol-defined cookie input in its canonical position;
5. verify the MAC in constant time before dispatching on unauthenticated header
   semantics; and
6. erase derived key material with the same lifecycle as the packet handshake
   state.

The preserved checkpoint's chaining-key-derived construction and payload
coverage are useful implementation input. Its exact KDF label, stage, header
layout, timestamp unit, flags, and transcript are **not** approved until the
layout ambiguity is resolved with OpenNHP and CSA.

## Decisions required before implementation

The protocol owners must publish an unambiguous byte-level profile covering:

1. Whether the IBC identity field exists in each cipher suite.
2. Exact Curve and GMSM header lengths and every field offset.
3. Exact major version or negotiated profile identifier.
4. Timestamp width, unit, endianness, and freshness window.
5. Flag bit assignments and required-zero behavior.
6. MAC algorithm, output size, KDF input, domain label, and derivation stage.
7. Canonical MAC input ordering for the header, payload ciphertext, AEAD tag,
   and optional cookie.
8. Whether keepalive and bodyless messages use the same construction.
9. Maximum packet and payload sizes after the framing change.
10. Silent-drop, error-reporting, and telemetry behavior for unsupported
    versions and invalid MACs.

The resolved profile must be recorded as a normative field table plus byte
offset diagram. Prose totals alone are not sufficient.

## Required conformance vectors

No producer may emit the new profile until one immutable vector corpus covers
all implementations. Every vector must record the producer repository and
commit, profile/major version, cipher suite, keys or deterministic seed,
plaintext, ciphertext, serialized header, MAC input, derived MAC key, final
packet bytes, and expected result.

Required positive vectors:

- Curve packets with zero-length, short, and maximum permitted bodies;
- the domestic/GMSM suite if it remains supported by the profile;
- request and response directions;
- cookie-free and cookie-bound packets;
- keepalive and every permitted bodyless message;
- cross-language Go, browser/TypeScript, and qurl-go relay round trips; and
- current NHP 1.1 vectors retained unchanged beside the new corpus.

Required negative vectors:

- each header field changed independently;
- payload ciphertext and body AEAD tag changed independently;
- MAC produced with the wrong direction, peer, chaining key, derivation stage,
  domain label, or cipher suite;
- truncated and oversized headers or payloads;
- identity-present and identity-absent layout confusion;
- timestamp unit and boundary confusion;
- unknown flags and nonzero reserved fields;
- a version byte changed without recomputing the transcript; and
- a valid packet from one profile presented to the other profile's decoder.

CI must regenerate vectors only through a deliberate producer workflow and
must independently verify checked-in bytes. Consumer tests must not call the
producer implementation to compute their expected result.

## Version and downgrade behavior

- NHP 1.1 decoders must never reinterpret a new-profile packet as 1.1.
- New-profile decoders must select the layout from an authenticated deployment
  profile or the new major version before parsing variable offsets.
- Unsupported majors are silently dropped at the network boundary and counted
  only through non-sensitive aggregate telemetry.
- A failed new-profile attempt must not automatically retry with 1.1. That
  creates an active downgrade oracle.
- If temporary dual support is required, profile selection must be explicit
  and pinned per peer or deployment. It must not be inferred from attacker-
  controlled packet failures.
- Removing 1.1 read support requires separate evidence that every authorized
  producer has moved and that rollback no longer depends on 1.1.

## Coordinated rollout

1. **Resolve the specification.** Obtain a written CSA/OpenNHP decision on the
   identity field and exact 160/224 versus 240/304 layout.
2. **Freeze vectors.** Land byte-exact vectors and independent verifiers before
   production codec changes.
3. **Land consumers first.** Deploy dual-read capability with emission still
   fixed to 1.1. Keep the new path gated off by default.
4. **Prove observation.** Verify unsupported-major, invalid-MAC, and profile-use
   telemetry without exposing an oracle to unauthenticated peers.
5. **Enable bounded producers.** Opt in sandbox producers by explicit peer
   profile, then canary each server, AC, Go agent, browser agent, relay, and SDK
   implementation.
6. **Make the new profile default.** Only after cross-version journeys and
   rollback drills pass across the entire fleet.
7. **Retire 1.1 deliberately.** Remove legacy emission first. Remove legacy
   reads only in a later release with fleet evidence and a documented recovery
   plan.

Rollout is consumer-first and producer-last. There must be no interval where a
producer emits packets that a required consumer cannot parse.

## Merge gates for the eventual implementation PR

- CSA/OpenNHP layout ambiguity resolved in writing.
- New major or negotiated profile approved; no NHP 1.2 hard cut.
- Normative field offsets and MAC transcript documented.
- Cross-language positive and negative vector corpus green.
- Downgrade and wrong-profile journeys green.
- Dual-read and rollback behavior tested in sandbox.
- Consumer-first rollout ledger reviewed for every binary and generated
  browser artifact.
- No durable session-control semantics are coupled to the new envelope.
- No claim of NHP-standard compatibility exceeds the resolved publication.

Until every gate is satisfied, the preserved 160-byte/keyed-MAC code is a
research checkpoint only and must not be merged or deployed.

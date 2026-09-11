# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-09-11

### Fixed

- When every candidate failed before its request was sent, `Call`,
  `CallWithUCAN`, `CallWithCertChain`, `OpenStreamDirect`,
  `OpenStreamDirectWithCertChain`, `Resolve`, `ResolveWithCertChain` and
  `GetDirect` report the most recent candidate's failure at their deadline.
  A later pass that found no candidate, or a DHT lookup that failed, took
  its place, so a refused dial could come back as
  `ErrProcedureNotAdvertised`, `ErrContentNotAnnounced` or the lookup's own
  error.

## [0.8.0] - 2026-09-11

### Breaking

- `Resolve`, `ResolveWithCertChain` and `ResolveStationEndpoint` take a
  `context.Context` as their first argument. Without a deadline,
  `DefaultResolveTimeout` (10 s) applies. An error at the deadline joins the
  last failure with the context's error.
- A gated call (`ucan.Required`) is accepted only when the token's audience
  is the calling identity's node ID as lowercase hex, so tokens must be
  minted with that audience. `Policy.Check` takes the caller alongside the
  token, and returns `ErrNoCaller` or `ErrWrongAudience` when either is
  missing or they don't match.
- A provider answers only CALLs signed by the caller they name.
  `ServeOneCall` and `ServeOneCallGated` verify an inbound CALL's signature
  against its `caller` field before any policy or handler sees it, and give
  any other CALL no reply.

### Changed

- Direct dial treats every advertisement that verifies as a candidate, in the
  order the DHT returns them. A candidate whose station endpoint can't be
  resolved, whose dial fails, or whose dialed identity doesn't match is
  passed over for the next before the request is sent; once a CALL or a
  stream's opening frame may have gone out, its outcome stands. Resolution
  asks the DHT again after a pause that doubles from 100 ms to 1 s, and tries
  a candidate that failed again only when its advertisement or endpoint
  record has changed.
- `Call`, `CallWithUCAN` and `CallWithCertChain`: `timeout` bounds
  resolution, dials and the CALL. `OpenStreamDirect` and
  `OpenStreamDirectWithCertChain`: `timeout` bounds resolution and dials.
  `GetDirect`: `timeout` bounds lookups, dials and transfers, and a fetch
  that fails or doesn't verify moves on to the next provider. `PutDirect`:
  `timeout` bounds the endpoint lookup and the dial.

### Added

- `dht.FindRecordTimeout` and `dht.FindRecordsTimeout` bound one lookup by a
  given timeout.

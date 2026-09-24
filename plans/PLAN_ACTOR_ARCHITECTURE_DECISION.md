# PLAN_ACTOR_ARCHITECTURE_DECISION.md

**Status:** Decision recorded — implementation not started
**Created:** 2026-09-12
**Last Updated:** 2026-09-12

## End goal

> So macula-go's lifecycle bugs (the leak survey, retired on 2026-09-24 with the 10.x code it surveyed; its lessons carry into `PLAN_MACULA_12_RUNTIME.md` B7b/B7c)
> are fixed by supervision discipline — not one patch at a time — while
> its public API stays plain Go and its consumers never see a framework.

## Context

- The 2026-09-12 leak survey found the lifecycle bug classes every
  hand-rolled port inherits: stream teardown, unbounded fan-out, timer
  leaks, dropped-session leaks. The Erlang core is immune to these
  classes because of OTP supervision — the fix direction for macula-go
  is the same discipline, not more patches.
- `macula-lazymesh` has decided to adopt **Ergo** as its actor core
  (decision D4 in its gaps plan; `RESEARCH_ERGO_FOR_LAZYMESH.md` verdict:
  GO-WITH-CONDITIONS). This decision extends the same model downward:
  macula-go becomes actor-based **internally**, once lazymesh has proven
  the patterns.
- Go is the second-highest-leverage SDK decision after dotnet:
  macula-ts wraps macula-go's native layer, so this decision propagates
  to the TS binding for free (`EXPLORATION_ACTOR_MODELS_SDK_FAMILY.md`,
  "bindings inherit").

## Decisions

1. **Actor internals, not an actor API.** Ergo types (`Process`,
   `Mailbox`, `TerminateReason`) never leak to consumers. The public
   API stays plain Go (Session/Subscription/StationPool/DirectDial as
   today); actors live behind it. The mapping is direct: `PooledLink`
   → supervised actor (RunLinkAsync is already a supervisor with flat
   backoff), `Subscription` → actor, session reader → actor,
   dedup/replay → actor state.
2. **The host owns the node runtime.** macula-go does not start Ergo's
   embedded node; it accepts an injected runtime/config from the host
   (lazymesh, macula-mcp, a third party). Two libraries can't fight
   over a global node. Always `NetworkModeDisabled` — Ergo's default
   silently binds TCP :11144, which is exactly the open surface we
   rejected for lazymesh's control protocol.
3. **Sequence: lazymesh first.** The lazymesh supervision tree (root →
   realm actors → session actors + view-model actors) proves the model
   in an application; macula-go's port follows, reusing the same
   patterns and the same boundary discipline.
4. **Boundary rule for I/O.** QUIC reads/writes and LLM calls stay
   outside actors; results return as messages. Consequence of Go's
   model (see the caveat): supervision buys clean restart-after-death,
   bounded mailboxes, deathwatch and lifecycle — **not preemption of
   blocked goroutines**. A goroutine stuck in a syscall cannot be
   killed by any supervisor; interrupt remains ctx-cancel. This limit
   is identical in the current channel architecture, so actors still
   win on everything else.
5. **Version pin + bus-factor awareness.** Pin Ergo v1.999.330
   (breaking-major history), accept bus factor 1, re-evaluate at the
   first major that breaks us.

## Gateway actor

The seam between lazymesh and macula-go: the gateway actor owns the
macula-mcp subprocess and multiplexes realm subscriptions via
per-realm subscription children — which are exactly the pool/subscription
actors macula-go exposes once internals are actor-based. Until then the
gateway wraps the plain-Go API; after the port it *is* the pool.

## Phases

- [ ] Phase 1 — lazymesh proves the tree (see its gaps plan, D4).
- [ ] Phase 2 — macula-go internals port: PooledLink/Session reader/
      Subscription as supervised actors behind the unchanged public API;
      host-injected runtime; `NetworkModeDisabled` everywhere.
- [ ] Phase 3 — gateway actor replaces the channel↔actor seam.
- [ ] Phase 4 — macula-ts inherits (no TS-side changes expected; the
      native layer carries the discipline).

## Files to Create/Modify

| File | Purpose | Status |
|------|---------|--------|
| `internal/` internals | actor-based pool/session/subscription internals | Not started |
| (leak survey) | survey findings re-targeted at actor fixes | Retired 2026-09-24 with the 10.x code (B7a); lessons in `PLAN_MACULA_12_RUNTIME.md` |
| `EXPLORATION_ACTOR_MODELS_SDK_FAMILY.md` (macula-architecture) | Go row: gates fired | Updated 2026-09-12 |

## Success Criteria

- [ ] Public API unchanged; all existing tests pass against actor
      internals without modification.
- [ ] A killed link actor restarts with replay, matching current
      RespawnDelay behavior, with restart intensity in place of unbounded
      respawn.
- [ ] No Ergo types appear in any exported signature.
- [ ] The host can embed macula-go in-process without starting its own
      node runtime.
- [ ] The leak survey's stream-teardown and fan-out findings are closed
      structurally (actor teardown), not by patched try/finally.

## Open questions

- When Ergo's next major lands: pin-and-stay vs fork vs migrate?
- Does macula-mcp adopt the same actor internals, or stay a thin
  consumer? (Not decided — consumer either way.)

# nmap_extended Agent Playbook

## Mission
Transform this Nmap fork into a daemon-capable service with a secure websocket control plane (Boost.Beast) so external clients can invoke scanning features and receive structured progress/results.

## Primary Objectives
1. Keep existing Nmap functionality intact while adding service mode.
2. Add a control-plane API over websocket for command/request and event/response flows.
3. Enforce secure-by-default behavior in all new components.
4. Maintain a clear separation between scan engine internals and remote interface logic.

## Non-Negotiable Constraints
1. Do not break current CLI behavior unless explicitly asked.
2. Prefer incremental, reviewable changes over broad refactors.
3. New networking/control-plane code must be isolated from scanning logic behind explicit interfaces.
4. Every externally reachable action must have input validation and permission checks.

## Style and Convention Reminders
1. If TypeScript is introduced (tools, clients, helpers), use these conventions:
   - Types: snake_case + `_t`
   - Interfaces: snake_case + `_i`
   - Variables: snake_case
   - Standalone function names: PascalCase
   - Classes: PascalCase
   - Class methods: camelCase
   - Method/function params passed as objects where parameters are needed
2. Keep comments concise and focused on intent/security rationale.
3. Preserve existing project language/style in C/C++ areas unless asked to normalize.

## Architecture Direction
1. Introduce a `service/daemon` runtime mode.
2. Add a websocket server layer (Boost.Beast) for authenticated client sessions.
3. Define a strict message schema:
   - Request: command + args + request_id
   - Response: request_id + status + payload/error
   - Event: progress/log/result + correlation fields
4. Use a command dispatcher that maps websocket requests to approved internal actions.
5. Run scans through controlled job orchestration (queue, lifecycle, cancel, timeout).
6. Keep result streaming asynchronous and bounded.

## TypeScript Client Track (`./nmap_extended_ts_client/`)
1. Treat `./nmap_extended_ts_client/` as a first-class, full TypeScript project for control-plane clients.
2. Target use cases:
   - Programmatic API client library for websocket control-plane interactions.
   - Optional CLI wrapper for invoking common scan workflows.
   - Example app/scripts demonstrating connect/auth/request/stream/result handling.
3. Baseline project expectations:
   - `package.json`, `tsconfig.json`, lint config, test config, and build scripts.
   - `src/` with modular client components (transport, protocol, auth, job/session API).
   - `tests/` with unit tests and protocol contract tests.
   - `README.md` with setup, usage, and protocol compatibility notes.
4. Client architecture expectations:
   - Strongly typed request/response/event models aligned with control-plane schema.
   - Reconnection strategy with bounded backoff and jitter.
   - Request correlation and timeout/cancellation support.
   - Event subscription API for progress/log/result streaming.
5. Security expectations:
   - Secure defaults (`wss`, certificate validation, explicit unsafe overrides only).
   - Token/credential handling isolated from logs and error surfaces.
   - Input validation before outbound requests.
6. Compatibility expectations:
   - Version-aware handshake between client and daemon.
   - Graceful handling for unsupported commands or schema mismatches.
   - Keep protocol adapters isolated to simplify future control-plane evolution.

## Security Baseline
1. Bind control plane to localhost by default.
2. Require explicit opt-in for non-local bind addresses.
3. Add authentication before accepting privileged commands.
4. Prefer TLS (`wss`) whenever remote access is enabled.
5. Validate message size, schema, types, and allowed enum values.
6. Enforce limits:
   - Max frame/message size
   - Rate limits per client
   - Max concurrent jobs
   - Idle/session timeouts
7. Avoid shell invocation for request handling.
8. Sanitize and structure logs; never log secrets/tokens.
9. Ensure safe shutdown: close sessions, stop accepts, drain/abort jobs predictably.

## Phased Execution Plan
1. Baseline and map integration points
   - Identify startup flow and long-running loop options.
   - Determine where daemon mode can be introduced cleanly.
2. Add daemon mode scaffold
   - Service lifecycle: start, run, signal handling, stop.
3. Add control-plane skeleton
   - Beast listener, websocket session handling, basic ping/health route.
4. Add command protocol and dispatcher
   - Typed request parsing, validation, routing, structured error model.
5. Connect scan orchestration
   - Job create/status/cancel, progress and result events.
6. Harden security
   - AuthN/AuthZ model, limits, TLS wiring, abuse handling.
7. Test and verification
   - Unit/integration tests for protocol, auth, and lifecycle edge cases.
8. Build TypeScript client project (`./nmap_extended_ts_client/`)
   - Bootstrap package/tooling and enforce repository naming conventions.
   - Implement websocket transport, protocol types, and high-level client API.
   - Add tests, examples, and usage documentation tied to daemon capabilities.

## Working Checklist for Each Change
1. Define threat/abuse cases for the new endpoint or behavior.
2. Document defaults and failure behavior.
3. Add or update tests for success and failure paths.
4. Confirm backward compatibility for existing Nmap usage.
5. Verify logs and errors do not leak sensitive details.

## Documentation Requirement
When `README.md` is modified, keep a section at the bottom stating:
1. The code is primarily for the maintainer's personal purposes.
2. Stability is not guaranteed.
3. Users adopt and run it at their own risk.

## Decision Log Expectations
For significant architecture decisions, record:
1. Decision made.
2. Why alternatives were rejected.
3. Security implications.
4. Operational impact (performance, compatibility, maintainability).

## Current Nmap Architecture Findings (Control-Plane Planning)
1. Runtime model today is effectively single-process, single-scan, and heavily global-state-driven.
   - Core options/state are in global `NmapOps o`.
   - Additional global/static state exists in scan/orchestration paths (`ports`, `ftp`, delayed options, XML writer state, NSE Lua state, service-probe caches).
2. Existing scan execution is blocking and monolithic from `nmap_main(...)` through host-group and scan-type loops.
   - This means a control-plane listener cannot share the same thread and remain responsive.
3. Nmap currently relies on internal async I/O loops (select/nsock) rather than a multi-thread architecture.
   - Do not begin with a full threading rewrite of scan internals.
4. Error handling is process-fatal in many paths (`fatal`/`pfatal` call `exit(1)`).
   - Any untrusted control-plane input must be validated before touching scan internals.
5. `nmap_main` and related global state are not currently designed for safe concurrent in-process jobs.
   - Default assumption: one active scan job at a time until a deep refactor is completed.
6. TTY/signal behavior can interfere with daemon semantics.
   - Daemon/service mode must force non-interactive behavior and avoid terminal/signal handler side effects intended for CLI sessions.
7. Re-entrancy is limited.
   - Although `NmapOps::ReInit()` exists, the broader runtime uses many globals/static objects that are not comprehensively reset/reinitialized for repeated, concurrent service workloads.
8. Build-system note for Beast integration.
   - Current build system does not pin a C++ standard level in `Makefile.in`; define and enforce a required C++ standard explicitly before introducing Boost.Beast/Asio-based code.

## Recommended Control-Plane Integration Strategy
1. Phase 1 (lowest risk): daemon + websocket control plane orchestrates scans via isolated worker execution boundary.
   - Prefer process isolation for scan execution to prevent a single scan failure from terminating the control-plane daemon.
   - Stream structured events/results back to clients from worker output channels.
2. Phase 2: optional in-process execution path once robust guardrails exist.
   - Add explicit lifecycle management, strict request validation, and panic/failure containment strategy.
3. Concurrency policy (initial):
   - Start with `max_concurrent_scans = 1` per daemon instance.
   - Scale out using multiple daemon instances/process workers before attempting deep internal concurrency refactors.

## Service-Mode Guardrails
1. Never pass raw client-provided CLI strings directly into argument parsing.
2. Use validated command DTOs and an allowlisted command builder.
3. Enforce per-job timeouts, cancellation, and resource limits.
4. Ensure daemon shutdown policy is explicit and does not rely on CLI-era signal behavior.

## Build and Verification Notes
1. In this environment, final link of `nmap` required `-libverbs` because bundled `libpcap` compiled RDMA support (`pcap-rdmasniff`) and exported unresolved `ibv_*` symbols otherwise.
2. Under restricted sandbox execution, daemon socket bind and raw-socket scan operations can fail with `Operation not permitted`; run runtime control-plane/integration verification on a host context with socket permissions.
3. TypeScript client verification requires installing local `npm` dependencies in `./nmap_extended_ts_client/` before `npm run build` / `npm test`.

## Valgrind Quality Gate (Milestone Blocking)
1. Run `check-valgrind` before milestone completion and before release/package handoff.
2. Required analyzers: `memcheck` and `helgrind`.
3. Use reduced deterministic smoke scan targets for valgrind workflows:
   - `192.168.11.7`, `192.168.11.1`, `192.168.11.255`
   - scan args: `-n -Pn -sT -p 22`
4. Keep full `192.168.11.1/24` validation outside valgrind runs for broader functional checks.
5. Commit and maintain suppressions in `./packaging/valgrind/nmap_extended.supp` for known third-party/toolchain noise only.
6. Block milestone completion on unsuppressed:
   - memcheck invalid access/use-after-free/definite leaks
   - helgrind race/lock-order findings in project code
7. Persist valgrind logs and summary artifacts in `./dist/valgrind/` for triage and regression comparison.

## TypeScript SDK Release Gates
1. Package identity is `@opsimathically/nmap-extended-sdk` and release baseline is `1.0.0` with strict semver (breaking changes require major bump).
2. Publishable SDK outputs are dual-module (`.mjs` + `.cjs`) with typed declarations and explicit `exports` entries for:
   - package root (`@opsimathically/nmap-extended-sdk`)
   - secondary CLI subpath (`@opsimathically/nmap-extended-sdk/cli`)
3. Public API surface is limited to root entrypoint exports (`src/index.ts`); deep import paths are intentionally not exported.
4. Required SDK gates before publish/release handoff:
   - `npm run preflight:sdk`
   - `npm run build`
   - `npm run typecheck`
   - `npm run test`
   - `npm run check:api`
   - `npm run pack:smoke`
5. API Extractor report in `./nmap_extended_ts_client/etc/nmap-extended-sdk.api.md` is committed and treated as the public API snapshot gate.
6. Changesets in `./nmap_extended_ts_client/.changeset/` control version bumps and release intent; release workflow must publish from generated changesets using `NPM_TOKEN`.

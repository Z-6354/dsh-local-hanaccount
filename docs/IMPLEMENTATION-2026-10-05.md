# Auth compatibility implementation evidence — 2026-10-05

Local branch: `codex/official-web-auth`. Plugin metadata stays at 2.4.1; these
working-tree changes have not been committed, published or deployed. Existing
App/parent documentation and official core sources were not edited. No production
listener, configuration, credentials or model API was accessed.

## Delivered

- One audited adapter owns native public-method/303/Cookie response assumptions,
  WebServer private route Maps/fallback descriptors and Cordis original-service
  proxy identity. Unknown/missing `officialBuild` refuses activation. Structural
  probes occur before route mutation. Declared build is operator attestation,
  never a measured running-binary claim.
- Core startup keeps wrapped routes closed until store, bridge, API and lifecycle
  disposer are installed. `ctx.effect` owns disposal; old `ctx.on('dispose')`
  did not fire as a lifecycle hook in this official source. Disposal/failed bridge
  init retains deny-only guards and closes tracked connections; reapply uses the
  same listener identity. Late route registration/fallback replacement remains
  wrapped. `ready` reports local guard activation and `deploymentReady` is false.
- `/assets` and `/plugins` have no broad GET/HEAD auth exemption. Private API
  handlers recheck native identity alongside the gate session. Cookies, original
  Host/Origin/IP fences and clean URL/password login remain intact.
- Password/session storage failures stop the activated core; logout emits
  revocation even if persistence fails. Active upgrades and tracked business HTTP
  responses close on revoke/dispose. Account-control JSON is excluded from long
  response tracking so logout/password-change acknowledgements stay writable.
  Already submitted background work is not cancelled. TTL checks remain every
  60 seconds and are not a zero-latency expiry guarantee.
- Passkey implementation is loaded only on optional Passkey requests. The server
  login reads a bundled snapshot of the v2.4.1 dialog CSS, without reading client
  code or requiring its module boot. Outbound global-fetch enhancement is opt-in,
  has its own failure boundary and cannot overwrite another owner's wrapper on
  disposal; retained wrapper chains stop injecting credentials.
- hanui may supply pure CSS through explicit canonical HTTPS origin plus exact
  same-origin `/hanui-assets/login.css` URL. Credentials, query, fragment,
  cross-origin, noncanonical URLs and other paths are rejected. Matching HTTPS
  transport or a trusted HTTPS-termination proxy is required. Inline local styles
  remain first, the optional stylesheet loads afterwards, and CSP permits only
  that validated URL. CSS loading never affects security readiness.

## Commands and observed results

Working directory `D:/0HAN/Work/deepseek-harness-mobile/dsh-local-hanaccount`:

1. Latest full-suite run after the final stale-stop/Passkey corrections:
   `npm test` — 106 tests: **100 passed, 0 failed, 6 skipped**. The six opt-in live
   attack tests stayed disabled and did not address production. Added eleven tests
   cover selection/failure, dispose/reapply, structural preflight, CSS safety,
   dynamic GET auth, long-response revoke, fetch ownership and logout-write failure.
   Eighteen additional independent-review regressions cover delayed body/remote
   requests, operation retirement, IP-policy revalidation, token/peer failure
   boundaries, Passkey failures and actual collection of permanent-guard route owners.
2. `npm run test:official -- D:/0HAN/Work/deepseek-harness` — **passed** all three
   source composition scenarios: supported auth lifecycle, deliberate optional
   plugin failure, unknown-build refusal. Actual official WebServer, Cordis Loader,
   HostConnectionService and BrowserAuth are loaded from source; credentials exist
   only in fixture memory, data dirs are temporary and listeners bind loopback on
   OS-selected ports. No official CLI or model service is loaded.
3. `git diff --check` — passed.
4. Latest covering run after the final corrections:
   `node --test test/adapter-lifecycle.test.js test/review-regressions.test.js test/password-native.test.js`
   — **43 passed, 0 failed, 0 skipped**. This includes all 11 adapter lifecycle,
   18 independent-review and 14 native/password cases. Root then requested the
   final full-suite rerun; its exact result is recorded in item 1.

Official source HEAD was measured with `git rev-parse HEAD`:
`0a15e36e7f82b6ed45af6fa9759f29b40dcd965d`. Official tracked source had no local
modifications when checked; unrelated untracked helper/documentation files were
present. WebServer/Connection metadata is `0.1.6-alpha.1`, Cordis source metadata
`4.0.2`, runtime `v24.19.0`; adapter `dsh-0a15e36-web-auth-v1`.
This is a source composition result, not a packaged-release certification. The
local prebuilt Cordis failed source Loader import (`FiberState` export mismatch)
when source aliases were not enabled. The obsolete full CLI probe was replaced
with an explicit source-fixture launcher; `--serve-for-qa` is unsupported.

The supported real fixture verifies clean password login -> two separate Cookies
-> actual official verification -> protected HTTP and Upgrade success; empty,
gate-only and native-only rejection; deep fallback; logout acknowledgement and
socket close within one second of local event; cookie replay rejection; hot
dispose 503/Upgrade rejection; reapply readiness. The latest rerun also verifies
an actual failed Passkey-revoke API response is 503 `storage_unavailable`, closes
a live official Upgrade connection, leaves core readiness false and rejects
subsequent business HTTP with 503. It also serves a real exact
fixture CSS route and checks the link plus static response with trusted proxy
headers. This is simulated HTTPS termination over local HTTP, **not a real browser
TLS/CSS rendering test**. Local login tests execute inline JS and retain the
24px card style; device/WebView visual QA remains a separate task.

While extending the source fixture, its first new re-login assertion exposed a
fixture omission: the reapplied operator configuration did not retain the
in-memory fixture password. Reapply now explicitly supplies that fixture hash.
A subsequent run hit fetch's forbidden-port check on an OS-selected loopback
port after the supported scenario passed. The fixture now uses Node HTTP for
its server-contract requests; redirects remain explicit and unfollowed. After
both fixture corrections the complete three-scenario command above passed.

## Public deployment is blocked

The failure fixtures deliberately prove that Loader does not stop siblings when
auth throws: fallback HTTP and Upgrade still succeed. A genuine signed native
Cookie minted by the fixture's official owner reaches the business handler after
an optional auth failure or unknown-build refusal. Throwing is therefore not an
all-path exposure control, and this implementation does not claim otherwise.

Retained guards improve hot disposal only after successful installation on the
audited dispatcher. Import failure, missing private structures, initial startup
before plugin installation, direct handler/Map/descriptor replacement and future
dispatch carriers cannot be made safe by this optional plugin alone. Integrity
checks reject through surviving wrapped paths but do not synchronously catch a
path whose wrapper was bypassed. The adapter is not a security boundary against
arbitrary in-process code.

Before any public rollout, an independently owned ingress must remain closed
until verified core readiness, close synchronously on missing/failed/disabled/
unloaded core, block direct upstream access, enforce every HTTP/Upgrade path and
close existing connections. Alternatively a required boot composition must prove
the listener never opens, and stops fully, under the same failures. This requires
real topology and timing evidence, including replayed native-only cookies; a
health URL/boolean and periodic polling alone do not suffice. No such control or
public topology was implemented or verified here. After persistence failure,
durable revocation/restart recovery must be established before ingress reopening.
Official native Cookies still have no per-session revocation API; retaining both
identities remains necessary. HTTPS proxy/TLS authority, binary packaging,
candidate upgrades and full external HTTP/SSE/upload revocation matrix remain
deployment acceptance requirements.

## Changed files

Core: `src/index.js`, `src/gate.js`, `src/api.js`, `src/lib/dsh-adapter.js`,
`src/lib/native-bridge.js`, `src/lib/store.js`, `src/lib/route-policy.js`,
`src/lib/tokens.js`, `src/lib/peers.js`, `src/lib/passkey-store.js`.
Optional presentation/enhancements: `src/lib/login-page.js`,
`src/lib/login-dialog.css`, `src/lib/login-style.js`, `src/lib/passkey.js`,
`src/lib/outbound-fetch.js`.
Configuration/evidence: `package.json`, `cordis.patch.yml`, `README.md`, this file,
`test/adapter-lifecycle.test.js`, `test/review-regressions.test.js`, `scripts/official-auth-fixture.mjs`,
`scripts/probe-isolated-host.mjs`.

## Independent-review corrections

R1: Every API request validates the current core owner and store lifetime. Body
completion, remote pairing fetch/JSON completion and optional Passkey verifier
completion recheck the same session/native identity, current password version and
IP policy before writes. Public login/setup also cannot persist through a retired
epoch. Core stop retires the store plus its child APIs before closing connections;
new epochs have distinct owner identities. Private synchronous mutations retain
only their own final bounded acknowledgement after revoking their session.
Regressions suspend config/key/token requests before body completion then log out,
suspend config/login/setup across same-directory reapply and compare disk snapshots,
and revoke a remote pairing request while it awaits its fixture response. All reject
without stale credential/config writes; fresh-generation sessions stay intact.

R2: Token, peer, pairing-code and Passkey writes normalize failure to `storage_unavailable`,
latch their stores unavailable, notify the common core stop callback and emit
security revocation even if persistence fails. Usage callbacks also check this
latch; a retry cannot skip a failed last-used write and authenticate through the
one-minute throttle. Token and peer management regressions verify immediate socket
closure/core unreadiness after failed revoke, and usage-write retries fail closed.
Durable recovery before reopening remains a deployment requirement.

Follow-up review caught Passkey persistence still bypassing the common stop
callback. Passkey revoke, registration, challenge and counter writes now share
the failure latch/core callback and guarded lifetime. Five focused regressions
cover the real revoke API acknowledgement plus socket closure, each mutation
class, a successful verifier followed by failed counter persistence, failed-store
retries and retired-store writes after reapply. The real official-source fixture
also exercises failed revoke through its actual HTTP dispatcher and Upgrade.

Follow-up review also caught an old adapter's late stop closing the shared guard
after unsupported-build refusal followed by a new apply. Each adapter now claims
an epoch before initialization; activation and stop require that exact owner.
Retired state cannot report another epoch's readiness. A regression checks the
refusal/reapply sequence, late activation rejection, repeated old stop, live
fallback dispatch and the new gate's disposal counter.

R3: Production installs the retained route adapter in permanent mode with no
per-route undo closures. It cannot be unwrapped; the reversible helper remains for
isolated tests only. Current handler wrappers do not cache prior gate/store owners.
A spawned Node process with `--expose-gc` performs 50 route/fallback/core epochs and
verifies all 150 weakly observed removed route, gate and owner objects are collected
while the permanent route layer stays installed. This tests actual collection,
not an implementation counter. The affected real official-source composition was
rerun successfully after these lifecycle changes.

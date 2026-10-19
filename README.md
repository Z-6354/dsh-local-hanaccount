# dsh-local-hanaccount — access lock for DSH Web

Single-operator **access gate** for a local DSH Web profile: password, Passkey, IP whitelist/blacklist, block statistics, and optional Nginx integration. Public device access and durable server notifications are not ready.

**Public deployment remains blocked.** Official Loader tolerates optional plugin
failures and keeps sibling listeners/routes running. A failed import, missing required interface,
missing dispatcher seat or a path outside the audited dispatcher can
therefore expose official-cookie-only access. Throwing from this plugin is not
a service shutdown guarantee. An external ingress must stay closed before
verified security readiness, close on security loss and own existing connection
teardown, or a required boot composition must prove equivalent behavior.

Compatibility uses interface and dispatcher capability checks, rather than a
DSH version or commit allowlist. DSH version changes alone do not reject
activation. The `dsh-capability-web-auth-v1` adapter requires public connection
`requestRejection`, `authenticatedUrl`, `authorizeIndex`, plus WebServer
`register`, `registerUpgrade`, `registerFallback`, writable Map route tables
(`exact`, `prefixes`, `upgrades`) and the supported fallback property shape.
Existing `officialBuild` configuration is retained as unverified metadata only.
Diagnostics report `compatibilityMode: capability-based`, detected capabilities
and guard readiness; this is not a claim about every future DSH version.
Missing methods report `native_bridge_unavailable` or `webserver_unsupported`;
check the named methods/route shape and install a compatible DSH/plugin build.
If the dispatcher changes after activation, the retained guard refuses requests
with `auth_unavailable`. `deploymentReady` remains false; HTTP page rendering
and the optional UI are not deployment approval.

RPC grants additionally need `connection.admit` and its public `browserPeer`
(rc.2) or legacy `operator` identity. Both the native browser cookie and current
plugin session/scope are still required; an admitted API peer cannot obtain a
browser grant. Missing RPC capabilities report `rpc_authorization_unavailable`
and the missing interface in diagnostics while ordinary password login remains
available. Integrations that require a grant must treat that error as unavailable.

## Features (v2.5.0)

- **Unified login page** — first visits and access-control logout use the previous Chinese access-control dialog, with server-configured initial password guidance and Passkey login.

- **Ordinary URL + password** — open the original HTTPS website without a token suffix. The `password-native-v1` bridge establishes both gate and official Host sessions.
- **Audited route protection** — wrapped HTTP business routes, fallback pages and WebSocket upgrades require both identities. `/assets` and `/plugins` are protected on GET/HEAD too. Prefix names cannot establish static ownership.
- **Revocation** — logout closes active upgrades and tracked business HTTP responses; account-control JSON acknowledgements remain writable. Already submitted server work is not cancelled. Key/passkey removal during an in-flight login cannot grant a new session.
- **Mobile integration** — compatible with the new password-only App. Old Relay pairing is not an App login route.

## Existing gate features

- **Protect-all routes** — wraps every plugin `webServer` prefix by default
- **Fail-closed business routes** — `excludePrefixes` cannot exempt authenticated business routes
- **Peer pairing** — cross-device Token; optional outbound `fetch` injection requires `outboundFetchEnabled: true` and is independently disposable
- **API tokens** — manual Bearer keys for scripts

## Features (v2.1)

- **Password login** — server-configured password; scrypt hash + lockout after 5 failures
- **Passkey login** — WebAuthn (HTTPS or localhost); fingerprint / Face ID in browser
- **IP whitelist** — trusted IPs pass IP gate without logging
- **IP blacklist** — permanent deny + block counter
- **Security visitors** — suspicious IPs from blocks / failed logins (not whitelisted traffic)
- **SSH key login** — `authorized_keys` + challenge/verify (ed25519)
- **Nginx snippet** — copy-paste reverse proxy config with `X-Real-IP`
- **Nginx Basic passthrough** — disabled; an unverified Basic header cannot authenticate
- **LAN mode** — disable the allowlist, while explicit deny entries and authentication remain enforced

Workspaces and sessions are **native DSH** — this plugin does not manage them.

## Install

```bash
dsh plugin --profile web add dsh-local-hanaccount
# or from local checkout:
dsh plugin --profile web add /path/to/dsh-local-hanaccount
```

Restart DSH Web profile after install.

### Optional login stylesheet

The built-in login page keeps the v2.4.1 dialog CSS in a server-owned static file,
without importing the client module or loading React. The hanui mobile stylesheet
is optional and must be deployed as a pure static resource at exactly
`/hanui-assets/login.css`. The official `/plugins` module route is not assumed
to serve arbitrary files. Configure an explicit canonical HTTPS origin and URL:

```yaml
canonicalOrigin: "https://your-host.example"
loginStylesheetUrl: "https://your-host.example/hanui-assets/login.css"
outboundFetchEnabled: false
```

Deploy hanui's packaged `src/login.css` to a separately owned static route or
proxy mapping, with `Content-Type: text/css`. Only exact GET/HEAD reads at that
configured origin/path may bypass the plugin session gate; upgrades, mutation
verbs and queries remain protected. Host/IP/Origin fences still apply inside
DSH. The stylesheet URL must have no credentials, query or fragment and must
match the canonical HTTPS origin. Invalid configuration or failed loading leaves
the local dialog usable; CSS never supplies authentication/readiness. CSP allows
the validated stylesheet URL only, alongside the inline nonce. A trusted HTTPS
termination proxy must remove forged forwarded headers and set the correct
external Host (including port) and proto.

### Local source compatibility checks

For a focused local check, run `node --test test/adapter-lifecycle.test.js test/rpc-authorization.test.js test/password-native.test.js` and `node scripts/bundle.mjs --check`. `npm test` runs the broader suite. With the historical audited official source checkout
and its existing dependencies, run
`npm run test:official -- /absolute/path/to/deepseek-harness`. This starts only
temporary loopback WebServer/Loader fixtures and in-memory fixture credentials;
no model service or existing DSH home is loaded. It proves the supported source
composition and separately demonstrates optional-loader exposure failures. It
does not validate packaged binaries, public ingress, TLS or future versions.
The former full CLI probe and `--serve-for-qa` mode are retired because the local
built packages differed from source. See
[the implementation evidence](docs/IMPLEMENTATION-2026-10-05.md).

### GitHub download

Download `dsh-local-hanaccount-2.5.0.tgz` from [GitHub Releases](https://github.com/Z-6354/dsh-local-hanaccount/releases/tag/v2.5.0). Extract the archive and install its `package` directory:

```bash
tar -xzf dsh-local-hanaccount-2.5.0.tgz
cd package
npm install --omit=dev
dsh plugin --profile web add "$PWD"
```

Restart the Web profile through your normal service workflow. Preserve the existing storage directory. The historical source fixture targets `0.1.6-alpha.1`; focused checks also cover the `./` native-cookie redirect from `0.2.1` and the rc.2 browserPeer interface. These checks do not establish packaged rc.2 or public deployment acceptance. Version changes are accepted when the required interfaces and route structure remain compatible.

## First run

1. **Set the access password on the server, not in the browser.** Browser setup is closed (`auth/setup` answers 403 `setup_disabled`): a tunnel into loopback (frp, `ssh -R`, cloudflared, ...) is indistinguishable from the local browser, so "first visitor sets the password" would let whoever reaches the port first take the instance. Choose one:
   - environment: `DSH_HANACCOUNT_PASSWORD_FILE=/path/to/file` (preferred) or `DSH_HANACCOUNT_PASSWORD=...`, then start DSH. It is applied only while no password exists and never overwrites one, so remove it afterwards;
   - or, with DSH stopped, `node scripts/set-password.mjs [--data-dir DIR]` (password from a hidden prompt, piped stdin or the environment variables above, never from argv). It refuses to replace an existing password unless `--force` is given, which signs every session out.

   Minimum length is 8. Until a password exists the login page only explains this.
2. If your IP is not whitelisted, add it under **Settings → 访问控制**
3. For remote access, use HTTPS and a deliberately configured trusted reverse proxy. Public device capabilities require additional Host authentication and authorization work.

### Network policy (IPv4 only)

- **IPv4 only.** A remote IPv6 client is refused with 403 (`ipv6_not_supported`), because every address of a /64 would otherwise be its own identity for lockout and allow/deny matching. `::1` (local) and IPv4-mapped addresses (`::ffff:a.b.c.d`) still work. Make sure your reverse proxy reaches DSH, and presents the client, over IPv4.
- **Loopback is not 免登录 by default.** A connection from `127.0.0.1` could be a tunnel terminating on this host, so even the local browser logs in with the password. Set `"loopbackOperator": true` in `config.json` (or `PUT config`) to restore 免登录 for loopback. Explicit `allow` entries for remote IPv4 addresses are unaffected.
- **Forwarding headers on a loopback peer fail closed.** If a loopback connection carries any forwarding header (`X-Forwarded-*`, `X-Real-IP`, `Forwarded`, `Via`, `CF-*`, ...) but no trustworthy client address can be derived, the client is treated as an unresolved proxy client: never whitelisted and sharing one lockout bucket. The client address is `X-Real-IP`, or the **right-most** `X-Forwarded-For` hop; when both exist they must agree. The nginx snippet in the UI satisfies this.
- Login lockout state is bounded (2048 entries; active locks are evicted last).
- **Global login budget.** Per-address lockout (5 tries) cannot stop a guesser spread over many IPv4 addresses, so 30 failed password logins within 60 s put password login into a cooldown of 60 s, doubling to at most 15 min while the pressure continues (reset after a calm hour). Explicitly allow-listed addresses neither count toward nor are blocked by it; Passkey and key login are unaffected. State is in memory and resets on restart.
- **Non-blocking verification.** Passwords are verified with asynchronous scrypt (thread pool), at most 2 at a time with a queue of 8; beyond that the request gets 429 `login_busy` and is not counted as a failed guess. A flood can no longer freeze the event loop, so the DSH UI and sockets stay responsive.

## Data directory

`~/.dsh/storages/dsh-local-hanaccount/`

| File | Purpose |
|------|---------|
| `config.json` | password hash, allow/deny lists, toggles |
| `state.json` | sessions, lockouts |
| `authorized_keys` | SSH public keys |
| `passkeys.json` | Registered WebAuthn credentials |
| `security-visitors.json` | block stats + suspicious IPs |

## Login methods

| Method | When |
|--------|------|
| **Password** | Server-configured password + fallback |
| **Passkey** | HTTPS or `http://127.0.0.1` / `localhost` — register in Settings after first login |
| **SSH key** | Settings → advanced; for CLI/scripts (manual sign flow) |

Passkey availability is detected from the **current URL** (`isSecureContext`), not from whether you have a domain.

## Security and integration limits

Named HTTP routes, existing/later SPA fallback and registered upgrades are wrapped
through the audited WebServer Maps and fallback seat. New registrations through
the public registration methods are covered. Production disposal retains a
deny-only guard; a new plugin epoch can reapply to that same listener. Structural
probe failures refuse activation, but the optional Loader may continue serving
the listener. Direct handler/Map/descriptor mutation and new dispatch carriers
remain unsupported and may bypass the guard before integrity diagnostics detect
them. This adapter is version dependent and is not public Host middleware.
Configured `excludePrefixes` cannot exempt business routes. Only the configured
exact login stylesheet GET/HEAD path is eligible for public reading.

`password-native-v1` accepts an ordinary origin and password. Successful setup/password/passkey/key login returns two independent Set-Cookie headers: `dsh_gate_token` and the official authority-bound `dsh-auth-*` cookie. The trusted plugin uses only public `connection.requestRejection`, `authenticatedUrl`, and `authorizeIndex` in memory; the official owner mints and verifies its cookie. No internal token URL is sent to the client or requested over the network. External root/index token links redirect clean to `/` without exchanging them. Anonymous root/index serves a self-contained password page. `auth/me` exposes both `authenticated` and `nativeAuthenticated`; protected business requires both identities. Logout removes both cookies and revokes the gate, including active sockets. API/peer Bearer credentials remain operator credentials with no device scope. `/status.auth` advertises the password bridge separately from `deviceIntegration.ready=false`.

Sessions carry a password-version binding plus server-side absolute/idle lifetime (`sessionMaxAgeDays`). Password changes and logout invalidate credentials and close affected plugin-authorized sockets; token/peer revocation and deny-list changes recheck sockets synchronously. Session expiry on existing sockets is checked at most every 60 seconds, not per message. Existing sessions without the new binding must log in again. A durable, scoped device principal and per-operation authorization are still absent.

Pairing codes use cryptographic randomness, expire after ten minutes, are single use, and allow at most eight pending codes. Failed claims are bounded to thirty per ten-minute window globally (persisted) and ten per IP in each API handler; the IP bookkeeping is bounded. Token last-use writes are throttled to one minute. Bodies are limited to 64 KiB and ten seconds. JSON writes use an exclusive temporary file, content fsync, and atomic rename; errors propagate and corrupt JSON fails load. Directory fsync/power-loss durability is not promised on Windows. Cookies receive Secure for TLS and trusted proxy HTTPS; remote plain HTTP is unsuitable for credentials.

## Verification

`npm test` is offline by default. Live attack tests require both `DSH_ATTACK_OPT_IN=1` and an explicit `DSH_ATTACK_TARGET`; they can send wrong-password attempts, so use only a disposable Host you own.

`node scripts/probe-isolated-host.mjs <official-checkout>` runs a source-only official WebServer/Loader/HostConnectionService contract fixture on temporary local listeners, then closes them. It does not launch a full CLI, prompt a model, print credentials or serve a persistent QA host; `--serve-for-qa` is unsupported. Its existing optional Loader failure/fallback checks report `deploymentReady=false`; passing these fixtures is not a production deployment gate or full logged-in APP performance test.

### SSH key (CLI)

For headless/CLI use, add an `ssh-ed25519` public key under Settings → SSH 密钥.

## License

MIT

## Client authentication facts and UI preference scope

The client entry is generated deterministically from `src/lib/auth-session.js` with `npm run build`; `npm test` checks the bundle is current. Every plugin apply owns one fresh AuthSession, shared by LoginGate and optional Cordis `hanaccountAuth` service (`getSnapshot`, `subscribe`, `refresh`). Public snapshots contain only status/reason/scope/revision; unavailable transport does not assert logout, and dispose aborts/discards late requests.

### Stage A early authentication handoff

The optional same-origin bootstrap script starts the existing `/dsh-local-hanaccount/api/auth/me` request before the client bundle and offers its one `AuthSession` to the Cordis plugin. The plugin claims and reuses that session, so a completed bootstrap plus LoginGate mount performs one request; an unclaimed, expired, CSP-blocked, or re-applied bootstrap falls back to the ordinary client path. Logout publishes local revocation through `invalidate(reason)` and retires older refresh responses. The bootstrap carries no account snapshot, scope, cookie, or token.

Local alpha1 Cordis/React fixtures and the package test suite cover handoff, disposal, fallback, and re-apply. This source update has not been deployed or tested against a live DSH installation.

A gate session has an independent random non-credential `resumeScope`, stable across restarts of that login. `/auth/me` returns it only when gate and official native identities are both valid. Legacy valid sessions persist it once without renewing lifetime; storage failure fails closed. New login/password rotation/revocation yields a different partition. This value partitions UI startup preferences only and cannot authenticate any request; the system still has no separate multi-account tenancy model. Old clients may ignore it; new hanui conservatively disables cross-startup recovery when scope is absent.

The SPA AuthOverlay sends the existing empty readiness notification only after its own mounted visual frames, including an initially unavailable retry screen. Auth readiness is owned here rather than inferred by hanui DOM selectors. Scope/API migration failure, actual generated bundle reapply, single-flight reentry and initial unavailable overlay regressions are tested locally.

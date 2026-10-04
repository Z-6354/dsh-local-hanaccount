# dsh-local-hanaccount — access lock for DSH Web

Single-operator **access gate** for a local DSH Web profile: password, Passkey, IP whitelist/blacklist, block statistics, and optional Nginx integration. Public device access and durable server notifications are not ready.

## Features (v2.4.0)

- **Ordinary URL + password** — open the original HTTPS website without a token suffix. The `password-native-v1` bridge establishes both gate and official Host sessions.
- **Full route protection** — HTTP business routes, fallback pages and WebSocket upgrades require both identities; only GET/HEAD static resources are anonymously readable after entry/IP checks.
- **Revocation** — logout closes active sockets; key/passkey removal during an in-flight login cannot grant a new session.
- **Mobile integration** — compatible with the new password-only App. Old Relay pairing is not an App login route.

## Existing gate features

- **Protect-all routes** — wraps every plugin `webServer` prefix by default
- **Fail-closed business routes** — `excludePrefixes` cannot exempt authenticated business routes
- **Peer pairing** — cross-device Token; outbound `fetch` auto-injects Bearer
- **API tokens** — manual Bearer keys for scripts

## Features (v2.1)

- **Password login** — first visit sets password; scrypt hash + lockout after 5 failures
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

### GitHub download

Download `dsh-local-hanaccount-2.4.0.tgz` from [GitHub Releases](https://github.com/Z-6354/dsh-local-hanaccount/releases/tag/v2.4.0). Extract the archive and install its `package` directory:

```bash
tar -xzf dsh-local-hanaccount-2.4.0.tgz
cd package
npm install --omit=dev
dsh plugin --profile web add "$PWD"
```

Restart the Web profile through your normal service workflow. Preserve the existing storage directory. This release has been verified against the official built-lib `0.1.6-alpha.1`; private WebServer adapter compatibility with other versions must be checked before deployment.

## First run

1. Open DSH directly at localhost (without proxy headers) → set access password
2. If your IP is not whitelisted, add it under **Settings → 访问控制**
3. For remote access, use HTTPS and a deliberately configured trusted reverse proxy. Public device capabilities require additional Host authentication and authorization work.

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
| **Password** | Always (first-time setup + fallback) |
| **Passkey** | HTTPS or `http://127.0.0.1` / `localhost` — register in Settings after first login |
| **SSH key** | Settings → advanced; for CLI/scripts (manual sign flow) |

Passkey availability is detected from the **current URL** (`isSecureContext`), not from whether you have a domain.

## Security and integration limits

Named HTTP routes, the existing and later registered SPA fallback, and all registered upgrades, including `/api/remote.mux`, are wrapped synchronously through the current official WebServer route Maps and configurable fallback seat. New registrations and same-path replacements are covered; disposal restores current owners. Unknown structures and duplicate installation fail closed. Direct handler mutation and replacement of the Maps are unsupported. This private adapter is version dependent; it is not a supported public Host middleware interface. Configured `excludePrefixes` cannot exempt business routes; only built-in assets and plugin bundles are anonymously readable after IP and entry fences.

`password-native-v1` accepts an ordinary origin and password. Successful setup/password/passkey/key login returns two independent Set-Cookie headers: `dsh_gate_token` and the official authority-bound `dsh-auth-*` cookie. The trusted plugin uses only public `connection.requestRejection`, `authenticatedUrl`, and `authorizeIndex` in memory; the official owner mints and verifies its cookie. No internal token URL is sent to the client or requested over the network. External root/index token links redirect clean to `/` without exchanging them. Anonymous root/index serves a self-contained password page. `auth/me` exposes both `authenticated` and `nativeAuthenticated`; protected business requires both identities. Logout removes both cookies and revokes the gate, including active sockets. API/peer Bearer credentials remain operator credentials with no device scope. `/status.auth` advertises the password bridge separately from `deviceIntegration.ready=false`.

Sessions carry a password-version binding plus server-side absolute/idle lifetime (`sessionMaxAgeDays`). Password changes and logout invalidate credentials and close affected plugin-authorized sockets; token/peer revocation and deny-list changes recheck sockets synchronously. Session expiry on existing sockets is checked at most every 60 seconds, not per message. Existing sessions without the new binding must log in again. A durable, scoped device principal and per-operation authorization are still absent.

Pairing codes use cryptographic randomness, expire after ten minutes, are single use, and allow at most eight pending codes. Failed claims are bounded to thirty per ten-minute window globally (persisted) and ten per IP in each API handler; the IP bookkeeping is bounded. Token last-use writes are throttled to one minute. Bodies are limited to 64 KiB and ten seconds. JSON writes use an exclusive temporary file, content fsync, and atomic rename; errors propagate and corrupt JSON fails load. Directory fsync/power-loss durability is not promised on Windows. Cookies receive Secure for TLS and trusted proxy HTTPS; remote plain HTTP is unsuitable for credentials.

## Verification

`npm test` is offline by default. Live attack tests require both `DSH_ATTACK_OPT_IN=1` and an explicit `DSH_ATTACK_TARGET`; they can send wrong-password attempts, so use only a disposable Host you own.

`node scripts/probe-isolated-host.mjs <official-checkout>` launches an official Web CLI with an OS-assigned loopback port and temporary home/workspace, strips inherited credentials, points the model at an unavailable loopback URL, and cleans up its own process tree and files. It performs clean-client password login, dual-cookie verification, real RPC/session operations, Remote mux ready, passive session-event observation, canonical session snapshot, active Bearer revocation and gate logout. It never requests a token URL, prompts a model or registers a waterfall responder. Add `--serve-for-qa` to keep the isolated fixture available for up to 30 minutes; stdout prints only its ordinary origin, randomly generated fixture password and fixture session ID, and any stdin data stops it. These checks do not establish scoped device access, durable pending-request replay, or full P0/P3 readiness.

### SSH key (CLI)

For headless/CLI use, add an `ssh-ed25519` public key under Settings → SSH 密钥.

## License

MIT

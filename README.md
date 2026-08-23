# dsh-local-hanaccount — access lock for DSH Web

Single-operator **access gate** for exposing DSH on the public internet: password, Passkey, IP whitelist/blacklist, block statistics, and optional Nginx integration.

## Features (v2.2)

- **Protect-all routes** — wraps every plugin `webServer` prefix by default
- **Explicit expose** — `excludePrefixes` skips login only (IP rules still apply)
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
- **Nginx Basic passthrough** — optional auto-login when `Authorization: Basic` is present
- **LAN mode** — disable IP limits, password still required

Workspaces and sessions are **native DSH** — this plugin does not manage them.

## Install

```bash
dsh plugin --profile web add dsh-local-hanaccount
# or from local checkout:
dsh plugin --profile web add /path/to/dsh-local-hanaccount
```

Restart DSH Web profile after install.

## First run

1. Open DSH in browser → set access password
2. If your IP is not whitelisted, add it under **Settings → 访问控制**
3. For public internet: put Nginx in front, bind DSH to `127.0.0.1`, use the Nginx snippet from settings

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

### SSH key (CLI)

For headless/CLI use, add an `ssh-ed25519` public key under Settings → SSH 密钥.

## License

MIT

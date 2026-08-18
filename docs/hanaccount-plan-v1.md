# dsh-local-hanaccount plan v1

**Status:** planning only (no implementation in this doc)  
**Goal:** Finish the plugin so workspaces live in DSH native `workspaceRegistry`, and each logged-in browser/account only sees and can use its own workspaces.  
**Scope:** Host (`src/index.js`), client (`src/client.js`), tests; profile patch (`cordis.patch.yml` / `~/.dsh/profiles/web/cordis.patch.yml`) stays config-only unless a new config key is required.  
**Non-goals (v1):** Web registration, remote IdP, global DSH HTTP middleware, deleting physical directories on workspace delete.

---

## 1. Current state (evidence)

| Area | Today |
|------|--------|
| Auth | Cookie `dsh_lha_token` + `state.json` sessions; plugin APIs use `authUser(req)` (correct). |
| Plugin records | `state.workspaces[]` keyed by `owner`; ordinary paths under `dataDir/users/<user>/workspaces/`. |
| Native adopt | `ensureNativeWorkspace` → `workspaceRegistry.create` on **create / add-external only**; stores `nativeWorkspaceId`. |
| Registry patch | `patchWorkspaceRegistry` filters `list` / guards `create` / `resolveByPath` via `store.activeUser()` — **never called from `apply`**. |
| Identity for patch | `activeUser()` = `state.currentUser` (last successful `issueSession`) — **process-global**. |
| Client UI | `LoginGate` + account panel; **shadows** `sidebar.workspaces` at `priority: -100` with `AccountWorkspaceBrowser` (filter-only). |
| Delete | `DELETE /workspaces/:id` removes plugin row only; **no** native registry removal. |
| Config (live) | Profile patch enables plugin with local users (e.g. `hanruo` admin); `config` is whole-row replace, not deep-merge. |

---

## 2. Known gaps

### G1 — `patchWorkspaceRegistry` dead code

`apply` mounts the API prefix, `session/created` bookkeeping, and `provide('dshLocalHanaccount')`, but never invokes `patchWorkspaceRegistry`. Host-side list/create/resolve filtering therefore does nothing in production.

### G2 — `activeUser` is last-login global

`issueSession` writes `state.currentUser`; `activeUser()` reads that. Concurrent or sequential logins on one DSH process make the “current account” for registry patches equal to whoever logged in last—not the cookie on the request that triggered `list`/`create`/`resolveByPath`. Plugin HTTP APIs already use the cookie; the patch path does not.

### G3 — Client sidebar is a thin filter, not the full browser

`AccountWorkspaceBrowser` replaces the native `sidebar.workspaces` slot. It:

- Loads allowed rows from `GET /workspaces`
- Filters native `useWorkspaces` items by `nativeWorkspaceId` or path prefix
- Renders title, path, and open-session buttons only

Missing vs a full native browser (examples): create/open workspace flows that the stock UI provides, richer session grouping/actions, empty/error parity, and any future native features. Isolation depends on `nativeWorkspaceId` being populated; stale plugin rows without adopt show empty until recreate.

### G4 — No startup re-adopt

Existing `state.workspaces` after restart are not walked through `ensureNativeWorkspace`. If the native registry was cleared, rebuilt, or never got IDs, the client filter has nothing to match.

### G5 — Delete does not remove native registry entry

Deleting a plugin record leaves the native workspace (and its sessions) visible to any unfiltered consumer and to other accounts if G1/G2 are fixed incompletely.

### G6 — Secondary (related)

- Native “create workspace” UI (if still reachable) can bypass account roots unless host `create` is patched and identity is request-scoped.
- `session/created` owner bookkeeping is best-effort path match only; not a substitute for registry isolation.
- README claims host adopts + client filters; behavior is only partially true until G1–G5 land.

---

## 3. Constraints

1. **Supported extension points only** — Prefer `workspaceRegistry` service + client slots; do not patch DSH core or delete other users’ global rows from disk as a “filter.”
2. **Shared process, shared global registry** — One DSH process keeps a global native registry; isolation is **view/guard**, not separate registry files per account.
3. **Cookie is the account source of truth for HTTP** — `dsh_lha_token` already scopes plugin APIs; host filters must not prefer `state.currentUser`.
4. **Registry calls may lack `req`** — `workspaceRegistry.list|create|resolveByPath` may run from RPC/WS/internal code without an Express/Node request. Any host filter needs an explicit request/async context strategy, plus a safe fallback (deny / empty list) when identity is unknown.
5. **No physical delete** — UI/API delete remains “unlink record (+ native entry)”; directories on disk stay unless a later version opts in.
6. **Config replace semantics** — Profile `cordis.patch.yml` replaces the whole plugin `config` object; new knobs must be documented for operators.
7. **v0.1 product boundary** — No registration; users from local YAML; not a claim of full DSH HTTP middleware security.

---

## 4. Options A / B / C

### Option A — Wire host patch + request-scoped identity + keep (then thin) client filter

**Idea:** Call `patchWorkspaceRegistry` from `apply`. Replace `activeUser()` usage in the patch with **per-request / ALS identity** derived from the login cookie wherever a request exists; when no identity, `list` → `[]`, `create`/`resolve` → 401/undefined. On startup, re-adopt all plugin workspaces. On delete, remove native entry if the registry exposes delete/remove (else document limitation). Keep `AccountWorkspaceBrowser` as defense-in-depth until host filter is proven on the native list path; then optionally lower reliance on shadowing.

| Pros | Cons |
|------|------|
| Matches README architecture | ALS / request binding must be designed carefully |
| Closes G1–G5 in one ship | Temporary dual filtering (host + client) |
| Safer if native list sometimes lacks context | Slightly more code than B |

### Option B — Client-only isolation (leave host patch unused)

**Idea:** Do not call `patchWorkspaceRegistry`. Strengthen `AccountWorkspaceBrowser`, always ensure `nativeWorkspaceId` on create + startup re-adopt, improve empty states. Delete remains plugin-only or best-effort native delete from API handler only.

| Pros | Cons |
|------|------|
| Smallest diff | Native create / other registry consumers still see all accounts |
| No ALS problem | G1 stays; security boundary stays “UI + plugin API only” |
| | Fails the stated goal of host-scoped native registry use |

### Option C — Drop sidebar shadow; full native browser + host-only filter

**Idea:** Fix host patch + request-scoped identity (same as A). Remove `sidebar.workspaces` override so the stock workspace browser returns. Client keeps login gate + account panel (create under account root / external admin). Startup re-adopt + delete sync.

| Pros | Cons |
|------|------|
| Best UX parity with DSH | Blocked if native `list` path never carries cookie/ALS |
| True “use native registry + native UI” | Higher verification cost against DSH internals |
| Less client maintenance | Regression if identity missing → empty sidebar for everyone |

### Recommendation

**Ship Option A** as v1 completion path.

- It is the only option that both **activates** the existing host design and **keeps** UI isolation if request context is incomplete.
- Treat **Option C as a follow-up** once instrumentation proves every `workspaceRegistry.list` used by the sidebar runs under cookie/ALS-bound identity; then remove or demote `AccountWorkspaceBrowser`.
- **Reject Option B** for the stated goal (native registry isolation per account).

---

## 5. Precise change list

### 5.1 Host — `src/index.js`

1. **Invoke patch in `apply`**
   - After `createStore` / when `workspaceRegistry` is present: `const unpatch = patchWorkspaceRegistry(ctx, workspaceRegistry, store)`.
   - On `dispose`: call `unpatch()` alongside API disposer.

2. **Request-scoped identity (replace process-global for guards)**
   - Add something like `AsyncLocalStorage` (or DSH-supported request context if discovered) holding `{ user, token }`.
   - Populate from cookie in `createApiHandler` (wrap handler body) and any `webServer` hook available for non-plugin routes that touch workspaces.
   - Change patched `list` / `create` / `resolveByPath` to use `store.userFromContext()` (ALS → else optional explicit arg), **not** `store.activeUser()`.
   - Keep `state.currentUser` only as optional telemetry / “last login” for debugging, or stop writing it if unused—do not use it for authorization.
   - Fallback: no context → `list` returns `[]`; `create` throws 401; `resolveByPath` returns `undefined`.

3. **Startup re-adopt**
   - After patch: for each configured user, `listWorkspaces(user)` and `await ensureNativeWorkspace(...)` (sequential or lightly pooled).
   - Idempotent: if path already in registry, capture/update `nativeWorkspaceId` without duplicating rows (prefer `resolveByPath` then create-if-missing).

4. **Delete sync**
   - Extend `deleteWorkspace` API path: load record first (need `nativeWorkspaceId` / path), remove plugin row, then call native remove/delete if available on `workspaceRegistry` (confirm API name against runtime).
   - If no delete API: leave native row but ensure patched `list` still hides it for non-owners; document residual orphan risk for admins.

5. **`ensureNativeWorkspace` hardening**
   - Prefer resolve-by-path before create to avoid duplicate native entries on re-adopt.
   - Always persist `nativeWorkspaceId` when discovered.

6. **Tests (`test/basic.test.js`)**
   - Patch applied: mocked registry `list` filtered by context user, not `currentUser`.
   - Two sessions / two users: last login must not leak into the other user’s filtered list.
   - Re-adopt sets `nativeWorkspaceId` when registry returns id.
   - Delete removes plugin row and invokes native delete when stubbed.

### 5.2 Client — `src/client.js`

1. **Keep `AccountWorkspaceBrowser` for v1 (Option A)**
   - Continue `priority: -100` shadow.
   - After re-adopt, prefer matching on `nativeWorkspaceId`; path prefix as fallback only.
   - Improve empty / loading / error copy when `/workspaces` fails or IDs missing (point user to account panel create, not a broken native list).

2. **Account panel**
   - On successful create/add, rely on host adopt (already); refresh list.
   - Delete message: clarify native unlink when host supports it (“删除工作区记录与原生注册项（不删除磁盘目录）”).

3. **Do not expand into a full second workspace product UI** in v1 — avoid duplicating native browser features; path to Option C is removal of the shadow, not feature parity cloning.

4. **Optional later (post-verify):** remove `sidebar.workspaces` inject when host filter proven → Option C.

### 5.3 Docs / config

1. Update `README.md` “Account-scoped native sidebar” to match A: host patch **is** active; client filter is defense-in-depth; delete semantics; re-adopt on start.
2. No required profile YAML change for A unless a new flag is added (e.g. `filterNativeRegistry: true`); default on when plugin enabled.

### 5.4 Explicit non-changes

- Do not implement registration.
- Do not `rm -rf` workspace directories on delete.
- Do not clear other accounts’ native rows from the global registry “to isolate.”

---

## 6. Acceptance checklist

- [ ] `apply` calls `patchWorkspaceRegistry` and disposes the patch on shutdown.
- [ ] With users A and B logged in (separate browsers/cookies) against one DSH process, A’s sidebar/API workspace list never includes B’s paths or native IDs (and vice versa).
- [ ] Changing who logged in **last** on the server does **not** change what an earlier cookie session sees.
- [ ] Unauthenticated registry `list` (no ALS/cookie context) returns empty; `create` is rejected.
- [ ] Ordinary user cannot `create` a workspace outside their account root (host patch + existing API rules).
- [ ] Admin can still add external paths; those rows are owned by that admin and hidden from other users.
- [ ] After process restart, existing plugin workspaces regain / retain `nativeWorkspaceId` without manual recreate (re-adopt).
- [ ] Creating a workspace via account panel appears in filtered native data (`nativeWorkspaceId` set).
- [ ] Deleting a plugin workspace removes the plugin record and, when API exists, the native registry entry; disk folder remains.
- [ ] Login gate, sidebar entry, header chip, settings section still work.
- [ ] Unit tests cover context-scoped filter vs `currentUser`, re-adopt, and delete sync.
- [ ] README matches shipped behavior.

---

## 7. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Native sidebar `list` never runs under cookie/ALS | Host patch ineffective for stock UI; empty or wrong lists if shadow removed early | Stay on Option A with client filter until proven; instrument `list` call sites |
| Double-create on re-adopt | Duplicate native workspaces | Resolve-by-path before create; store id |
| Native delete API missing / different name | Orphans remain in global registry | Filter hides from non-owners; document admin cleanup; feature-detect delete |
| Over-filtering when context missing | Legitimate internal jobs see no workspaces | Narrow deny to user-facing paths; log once when context absent |
| Client id/path mismatch | Empty sidebar despite records | Startup re-adopt + prefer id match |
| Operators expect deep-merge config | Accidental wipe of `users` when patching | Keep README warning; avoid extra required keys |
| False sense of full HTTP lockdown | Other DSH routes still unauthenticated | Stay within v0.1 boundary; README security section |

---

## 8. Suggested implementation order

1. Request-scoped identity helper + stop authorizing on `activeUser`.
2. Call `patchWorkspaceRegistry` from `apply` + dispose.
3. Startup re-adopt + harden `ensureNativeWorkspace`.
4. Delete → native unlink (feature-detect).
5. Client copy / filter robustness only as needed.
6. Tests + README.
7. (Follow-up) Validate ALS on native sidebar path → Option C (remove shadow).

---

## 9. Decision summary

| Item | Decision |
|------|----------|
| Approach | **Option A** (host patch + cookie/ALS identity + keep client filter) |
| Follow-up | Option C when native list is proven request-scoped |
| Rejected | Option B as primary |
| Deliverable after this plan | Code + tests + README; this file remains the v1 plan reference |

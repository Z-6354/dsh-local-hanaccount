# dsh-local-hanaccount review v1

> Status: **Review complete — code agent may proceed**  
> Inputs: `docs/hanaccount-plan-v1.md`, `src/index.js`, `src/client.js`  
> Verified: `@deepseek-ai/dsh-workspace@0.1.0-rc.6` (`WorkspaceRegistry`: `list` / `create` / `resolveByPath` / **`delete(id)`**), `dsh-host-apiproxy` (`workspace.list` → `workspaceRegistry.list()` with no cookie), `dsh-client-connection` (`/api` HTTP bridge preserves Cookie headers), `dsh-host-webserver` (no middleware; prefix Map is runtime-accessible)  
> Scope: **review doc only** (this file). No implementation in this turn.

---

## 0. One-line verdict

**Adopt plan Option A with adjustments:** wire host `patchWorkspaceRegistry` + **AsyncLocalStorage (ALS) cookie identity** (never `activeUser` / `state.currentUser` for auth), startup re-adopt, native `delete(id)` sync, **keep** client `sidebar.workspaces` shadow at `priority: -100`; **reject** Option B; **defer** Option C.

---

## 1. Adopt / reject / adjust

| Plan item | Verdict | Reason |
|-----------|---------|--------|
| **Option A** (host patch + request-scoped identity + keep client filter) | **Adopt with adjustments** | Only path that activates dead `patchWorkspaceRegistry`, closes G1–G5, and keeps UI isolation when host context is incomplete. |
| **Option B** (client-only) | **Reject** | Leaves native registry unscoped; fails stated goal. |
| **Option C** (drop sidebar shadow; host-only) | **Defer (follow-up)** | Unsafe until `workspaceRegistry.list` used by sidebar **and** host event fan-out is proven always under cookie ALS. Mux/internal `list()` callers have no `req`. |
| Plan fallback: no identity → `list` `[]`, `create` 401, `resolve` `undefined` | **Adjust — reject as written** | `apiProxy` / fork / event paths call `list`/`create`/`resolveByPath` **without** HTTP context. Fail-closed empties every client store or breaks session workspace ensure. |
| “Pass `authUser` through plugin API only” | **Reject as sole strategy** | Registry patch runs outside `createApiHandler`; cookie must enter ALS (or explicit `runWithUser`) for patched methods. |
| Identity = `store.activeUser()` / `state.currentUser` | **Forbidden** | Process-global last-login; concurrent cookies leak (G2). May keep `currentUser` as debug telemetry only. |
| Delete native entry | **Adopt** | Runtime API is `workspaceRegistry.delete(id): Promise<boolean>` (registry row only; disk untouched). |
| Client keep `AccountWorkspaceBrowser` @ `-100` | **Adopt (mandatory for v1)** | Defense-in-depth; still required because some `list()` calls will remain ALS-less (pass-through). |
| Fork / patch `@deepseek-ai/dsh-workspace` sources | **Forbidden** | Use service method wrapping only. |

### Adjustment summary (vs plan §4–§5)

1. **ALS yes** (`node:async_hooks` `AsyncLocalStorage`), not “pass user through API only,” not process-global.
2. **Populate ALS from cookie** on: (a) plugin API handler, (b) **`/api` prefix handler wrap** so browser RPC `workspace.list|create|…` sees the same cookie, (c) explicit `runWithUser(user, fn)` for re-adopt / ensure / delete-side registry work.
3. **Patched method fallbacks when ALS empty:** **pass-through to originals** for `list` / `create` / `resolveByPath` (log once). When ALS has a user: filter / guard as planned.
4. Client shadow stays **required**, not “optional once host proven.”

---

## 2. CODING BRIEF (for code agent)

### 2.1 Files

| File | Action |
|------|--------|
| `src/index.js` | **Change** (main work) |
| `src/client.js` | **Keep** structure; small copy / robustness only |
| `test/basic.test.js` | **Add** tests listed below |
| `README.md` | **Update** Account-scoped section to match shipped A |
| `cordis.patch.yml` / profile YAML | **No change** unless you invent a flag (prefer none) |
| `@deepseek-ai/dsh-workspace` | **Do not fork / edit** |

### 2.2 Auth identity approach (mandatory)

**Use ALS + cookie. Do not authorize on `activeUser()`.**

```text
AsyncLocalStorage<{ user, token } | undefined>
  ├─ enter: createApiHandler (every request, from authUser(req))
  ├─ enter: wrap existing webServer `/api` prefix handler (cookie → authUser)
  ├─ enter: runWithUser(user, fn) for ensureNative / re-adopt / delete sync helpers
  └─ read:  store.userFromContext()  OR  authAls.getStore()?.user
             NEVER store.activeUser() inside patchWorkspaceRegistry
```

- Plugin HTTP APIs keep using `authUser(req, store)` for their own 401s (unchanged cookie flow).
- `state.currentUser` may still be written by `issueSession` for debugging; **must not** gate registry list/create/resolve.
- **`/api` wrap:** after `createStore`, locate `webServer.prefixes.get('/api')` (runtime field on `dsh-host-webserver`). If present, replace `route.handler` with a wrapper that `als.run({ user, token }, () => original(req, res))` where `{ user, token } = authUser(req, store)`. If missing at apply time, retry once on next microtask / `ctx.parallel` / short deferred — do not throw. Restore original handler in `unpatch` / dispose.
- This wrap is **plugin-local composition**, not a fork of dsh-workspace. Do not patch `dsh-client-connection` package files on disk.

### 2.3 Host — `src/index.js` (exact)

#### A. Add ALS helpers (module scope)

- `import { AsyncLocalStorage } from 'node:async_hooks'`
- `const authAls = new AsyncLocalStorage()`
- `function runWithUser(user, fn)` → `authAls.run({ user, token: null }, fn)` (sync/async capable)
- `function userFromAls()` → `authAls.getStore()?.user ?? null`

Export via `_internals`: `authAls`, `runWithUser`, `userFromAls`, `patchWorkspaceRegistry`, `ensureNativeWorkspace`, `wrapApiPrefixAuth` (or equivalent).

#### B. Store changes (`createStore`)

- Add `userFromContext()` → `userFromAls()` then `findUser` if store only has username (prefer storing full user object in ALS from `authUser`).
- Change `deleteWorkspace(user, workspaceId)` to **return the removed record or `null`** (not only boolean), so the API can read `nativeWorkspaceId` / path before/after removal.
- Keep `activeUser` exported if tests need it, but **patch must not call it**.

#### C. `patchWorkspaceRegistry(ctx, workspaceRegistry, store)` — rewrite identity + fallbacks

Keep monkey-patch of `list` / `create` / `resolveByPath` + `__dshLocalHanaccountPatched` + restore on dispose.

| Method | When `userFromAls()` set | When ALS empty |
|--------|--------------------------|----------------|
| `list` | Filter `original.list()` to paths owned / inside allowed plugin workspaces (same `inside` logic as today) | **Pass-through** `original.list()`; log once |
| `create` | 401 if no user (N/A); 403 if `!canUsePath`; then `original.create`; `recordWorkspace` with `nativeWorkspaceId` | **Pass-through** `original.create(...)` only (no recordWorkspace) |
| `resolveByPath` | If `!canUsePath && !ownsPath` → `undefined`; else original + re-check | **Pass-through** original |

Do **not** patch `delete` / `get` / `insertBefore` / `archiveSession`.

#### D. Invoke patch from `apply`

```text
apply:
  store = createStore(cfg)
  unpatchApi = wrapApiPrefixAuth(webServer, store)   // cookie → ALS on /api
  unpatchRegistry = workspaceRegistry
    ? patchWorkspaceRegistry(ctx, workspaceRegistry, store)
    : () => {}
  disposer = webServer.register({ prefix API_PREFIX, createApiHandler(...) })
  // wrap createApiHandler body in als.run from authUser (login/me/logout too)
  await reAdoptAll(store, workspaceRegistry)        // see E
  ctx.on('dispose', () => { disposer(); unpatchRegistry(); unpatchApi(); })
```

Today `apply` never calls `patchWorkspaceRegistry` — that is G1; fix it.

#### E. Startup re-adopt

- After patch: for each `store.users` (or each distinct `owner` in `state.workspaces`), `listWorkspaces(user)`, then for each ws `await ensureNativeWorkspace(...)` **sequentially** under `runWithUser(user, ...)`.
- Idempotent: see F.

#### F. Harden `ensureNativeWorkspace`

```text
runWithUser(user, async () => {
  1. Prefer resolveByPath(ws.path) when available (catch missing-path errors → treat as miss)
  2. Else / if miss: create(ws.path, title)  // upstream create is idempotent per canonical path
  3. Persist nativeWorkspaceId via recordWorkspace when id present and missing/outdated on plugin row
})
```

Do not require ALS pass-through path here — always enter `runWithUser`.

#### G. Delete sync (API `DELETE workspaces/:id`)

1. Resolve plugin row for this user+id (or use new `deleteWorkspace` return value).
2. Remove plugin row.
3. If `nativeWorkspaceId` and `typeof workspaceRegistry.delete === 'function'`, `await workspaceRegistry.delete(nativeId)` (feature-detect; ignore false/unknown).
4. **Never** `rm` / delete directories on disk.
5. Response JSON may note native unlink attempted.

#### H. `createApiHandler`

- Wrap entire handler (or each branch) in `authAls.run` after `authUser`.
- Login: after `issueSession`, subsequent requests carry cookie; optional: enter ALS with logged-in user for that response only (not required for set-cookie).
- **Do not break** `GET auth/me`, `POST auth/login`, `POST auth/logout`, cookie set/clear headers.

### 2.4 Client — `src/client.js`

| Item | Instruction |
|------|-------------|
| `AccountWorkspaceBrowser` | **Keep** |
| `priority: -100` | **Keep** — do not change without review follow-up |
| LoginGate / SidebarEntry / HeaderChip / SettingsSection | **Keep** behavior |
| Filter match | Prefer `nativeWorkspaceId`; path prefix fallback (already) |
| Empty / error copy | Light improve OK (“从本地账户面板创建”; show load error if `/workspaces` fails) |
| Delete toast | Clarify: 删除工作区记录与原生注册项（不删除磁盘目录） when host supports delete |
| Full native browser clone | **Forbidden** in v1 |
| Remove sidebar shadow (Option C) | **Forbidden** in v1 |

### 2.5 Tests — `test/basic.test.js`

Add (keep existing three tests):

1. **Context vs currentUser:** two users; set `state.currentUser` to B; `runWithUser(A, () => patched.list())` returns only A’s paths.
2. **No ALS list:** patched `list` equals original (pass-through).
3. **Re-adopt / ensureNative:** mock registry `resolveByPath` / `create`; after ensure, plugin row has `nativeWorkspaceId`.
4. **Delete sync:** mock `delete`; API or store helper invokes it with native id; plugin row gone; mock delete called.
5. Optional: patched `create` under ALS rejects path outside account root for role=user.

Export needed `_internals` so tests do not boot full Cordis.

### 2.6 README

Update “Account-scoped native sidebar”:

- Host patch **is** active; filters when cookie ALS is bound (`/api` + plugin API).
- Client filter remains defense-in-depth.
- Startup re-adopt; delete = plugin row + native registry `delete` (not disk).
- Security boundary unchanged (not global DSH auth middleware).

---

## 3. Acceptance tests / manual checks

### Automated

- [ ] `node --check src/index.js` / `src/client.js`
- [ ] `node --test test/basic.test.js` (existing + new) all pass

### Manual (one DSH web process, two browsers/profiles)

- [ ] Login A and B with different cookies; A’s sidebar/API never shows B’s workspaces (and vice versa).
- [ ] On server, login C “last”; A’s earlier cookie session list **unchanged**.
- [ ] Create workspace in account panel → appears in sidebar; `nativeWorkspaceId` set in `state.json`.
- [ ] Restart DSH → existing plugin workspaces regain/retain `nativeWorkspaceId` without recreate.
- [ ] Delete from panel → plugin row gone; native registry entry gone (`workspace.json` / UI); **disk folder remains**.
- [ ] Ordinary user cannot create outside account root (API 403).
- [ ] Admin external add still works; hidden from other users’ UI.
- [ ] Login / logout / remember cookie / overlay gate / header chip / settings section still work.
- [ ] Sidebar slot still shadowed (`priority: -100`); no sudden return of full unfiltered native browser as the visible slot.

---

## 4. Forbidden (code agent)

1. **Forking or editing** `@deepseek-ai/dsh-workspace` (or other DSH package sources) to add multi-tenant registries.
2. Using **`process-global` `activeUser` / `state.currentUser`** for host registry filter/guards.
3. **Breaking login cookie flow** (`dsh_lha_token`, `auth/login|logout|me`, HttpOnly Set-Cookie).
4. Changing **`sidebar.workspaces` `priority` away from `-100`** without a new review (Option C not in v1).
5. Physical **`rm -rf`** of workspace directories on delete.
6. Clearing **other accounts’** native rows “to isolate.”
7. Implementing **web registration** / remote IdP.
8. Fail-closed empty `list()` when ALS missing (breaks host events / client store).
9. Removing `AccountWorkspaceBrowser` in this ship.

---

## 5. Implementation order (code agent)

1. ALS helpers + `userFromContext` / stop patch→`activeUser`
2. Rewrite `patchWorkspaceRegistry` fallbacks; call from `apply` + dispose
3. Wrap plugin API + `/api` prefix with ALS from cookie
4. Harden `ensureNativeWorkspace` + startup re-adopt
5. Delete → `workspaceRegistry.delete`
6. Client copy tweaks only
7. Tests + README
8. `node --check` + `node --test`

---

## 6. Code agent may proceed?

**Yes.** Implement strictly per this BRIEF (adjusted Option A). Do not implement Option B or C.

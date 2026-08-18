# dsh-local-hanaccount

Open-source local account gate for the DeepSeek Harness Web profile.

**Native model (unchanged):** a **workspace is a directory**; **sessions live inside that workspace** (DSH `workspaceRegistry` + left sidebar WorkspaceBrowser). This plugin does **not** invent a second tree — it only gates login and scopes which directories each account may see/create.

- Local users only: v0.1 has **no web registration** and no remote account service.
- Users are configured in local Cordis/profile configuration.
- Login is remembered by a local cookie + local state file.
- Ordinary users may only use directories under their own account folder root.
- Admin users may also register arbitrary local paths.
- Per-account isolation is a **view/guard** over the shared native registry (cookie → ALS), not a separate session store.

MIT licensed.

## Install

```bash
cd ~/.dsh/profiles/web
pnpm add dsh-local-hanaccount
```

Add it to `dsh.profile.bundles` after the standard web bundle:

```jsonc
{
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base",
        "@deepseek-ai/dsh-web-app",
        "dsh-local-hanaccount"
      ]
    }
  }
}
```

Restart `dsh web`.

## Configure users

This plugin intentionally does not implement registration in v0.1. Configure local users by overriding the bundle row from the profile or home `cordis.patch.yml`:

```yaml
- id: dsh-local-hanaccount
  config:
    # 注意：DSH patch 中 config 通常按整段替换，不是深合并；
    # 因此这里把需要保留的配置项一起写出。
    enabled: true
    rememberLogin: true
    dataDir: ""
    users:
      - username: admin
        password: admin123
        role: admin
      - username: user1
        password: user123
        role: user
```

Passwords may be plain text. A simple SHA-256 form is also accepted:

```yaml
users:
  - username: user1
    passwordSha256: "<sha256-hex>"
    role: user
```

## Data layout

Default data directory:

```text
$DSH_HOME/storages/dsh-local-hanaccount
# or ~/.dsh/storages/dsh-local-hanaccount
```

Ordinary user workspace root:

```text
<dataDir>/users/<username>/workspaces/
```

The plugin stores its own state in:

```text
<dataDir>/state.json
```

Deleting a workspace from the UI removes the plugin record and the native registry entry when available; it does not delete the physical directory.

## Security boundary

v0.1 provides a Web UI login overlay and enforces permissions on the plugin's own APIs. It does not claim to be a global DSH HTTP middleware and does not patch DSH core. If a future DSH version exposes a supported workspace/session middleware hook, v2 can add deeper native filtering and account administration.

## Account-scoped native workspaces

Same as stock DSH:

| Native concept | Meaning |
|----------------|---------|
| Workspace | A filesystem directory registered in `workspaceRegistry` |
| Session | Lives under that workspace (`sessionIds` on the workspace entity) |
| UI | Left sidebar WorkspaceBrowser — create workspace = pick/create folder; open sessions under it |

What this plugin adds:

- **Login gate** + account cookie.
- **Host patch** on `workspaceRegistry.list` / `create` / `resolveByPath` scoped by ALS from that cookie (`/api` HTTP **and** `events.host` / `events.mux` upgrades). Ordinary users cannot create outside their account root; list only shows their root (plus recorded admin externals).
- **Directory picker** (`host.listDirectory` / `createDirectory`): non-admin browse home is the account workspace root; paths outside are clamped back. Workspace create remaps outside picks to `<accountRoot>/<basename>`.
- **Client filter** on `WorkspaceManager.upsert` / `installViews` so `host/workspace-changed` fan-out cannot show another account’s rows.
- **Session list filter** (host `sessions.list` + `sessionPersistence.list`, plus client `SessionManager`) so other accounts’ sessions do not leak into **未分组**.
- **Account panel** for login/logout and showing the account root path — **not** a parallel workspace UI. Admin「登记外部路径」入口已隐藏（host API 仍保留，需要时再恢复 UI）。
- When ALS has no user (internal callers), methods pass through (logged once).

Identity for registry guards is **never** last-login `currentUser`. Not a global DSH HTTP auth middleware.

---

## Changelog

### v0.1.1（2026-08-18）

**修复：删除工作区文件夹后，重启会被“加回来”**

- **问题**：用户在工作区里删除不需要的文件夹后，只要重启服务（或重启页面），被删的文件夹又会重新出现、并重新注册为工作区。
- **原因**：插件在启动时执行 `reAdoptAll()`，把 `state.json` 中记录的每个工作区重新“收养”进原生 `workspaceRegistry`。`ensureNativeWorkspace()` 对被删目录走 `resolveByPath` 无果后，会调用 `workspaceRegistry.create()` 重建——普通用户分支的 `patchedCreate` 会先 `mkdirSync(target, { recursive: true })` 把目录直接再建出来；同时 `state.json` 里的残留记录不会清理，列表里也继续显示。
- **修复**：
  1. `ensureNativeWorkspace()` 入口增加存在性检查——目录已被删除（`existsSync(ws.path)` 为假）的工作区直接跳过，不再收养、不再重建目录；
  2. `reAdoptAll()` 对被删除目录的工作区记录调用 `deleteWorkspace()` 清理，重启后列表与文件系统都不会“又加回来”。
- **回归测试**：新增 2 个用例（`reAdoptAll does not recreate workspaces whose directory was deleted`、`ensureNativeWorkspace skips workspaces whose directory was deleted`），共 13 个用例全部通过。

> 说明：删除文件系统文件夹 ≠ 调用插件 DELETE 工作区接口。此修复让“删除文件夹”成为最终删除动作，无需再在界面上额外删除工作区记录。

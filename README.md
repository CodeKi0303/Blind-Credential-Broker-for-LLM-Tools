# LLM Password Manager

Windows-only local password broker for LLM tool calling. The broker lets an LLM run approved SSH and DB tasks without ever receiving passwords, tokens, private-key passphrases, or connection strings.

## Current MVP

- MCP stdio server.
- Windows Credential Manager-backed secret storage.
- Native Windows password prompt when a credential is missing or fails connection testing.
- Native Windows approval prompt when a policy/profile requires explicit approval.
- Secret-free audit log.
- Client permission profiles independent of any specific LLM vendor.
- High-level MCP tools only:
  - `ssh_run`
  - `ssh_register`
  - `ssh_open_session`
  - `session_list`
  - `session_close`
  - `db_query`
  - `db_register`
  - `browser_login`
  - `browser_register`
  - `route_test`
  - `policy_check`
  - `credential_status`
  - `forget_credential`
  - `config_summary`
  - `audit_tail`
- CLI wrapper for agents that cannot speak MCP.
- SSH route graph with jump/nested SSH support.
- PostgreSQL and MySQL/MariaDB query support, including DB over SSH route.
- Managed Edge browser login for configured selector-based targets.

There is intentionally no `get_password`, `read_secret`, or `export_credential` tool.

## Build

```powershell
dotnet build .\LlmPwManager.slnx
```

Publish a portable self-contained Windows executable:

```powershell
dotnet publish .\src\LlmPwManager\LlmPwManager.csproj -c Release -r win-x64 --self-contained true
```

The single-file executable is written under:

```text
src\LlmPwManager\bin\Release\net10.0-windows\win-x64\publish\
```

## Run As MCP Server

```powershell
.\LlmPwManager.exe mcp
```

For an MCP client configuration, use the executable path and pass `mcp` as the first argument.

The executable can print MCP client snippets for the current machine:

```powershell
.\LlmPwManager.exe mcp-config
.\LlmPwManager.exe mcp-config --format mcpServers --name llm-pw-manager
```

The default output is a vendor-neutral stdio description:

```json
{
  "name": "llm-pw-manager",
  "transport": "stdio",
  "command": "C:\\path\\to\\LlmPwManager.exe",
  "args": ["mcp"],
  "env": {
    "LLM_PW_MANAGER_HOME": "C:\\Users\\you\\AppData\\Roaming\\LlmPwManager",
    "LLM_PW_MANAGER_CLIENT_PROFILE": "limited"
  }
}
```

## Run From CLI

Agents that cannot use MCP can call the same broker through CLI commands. Output is JSON and secrets are never printed.

```powershell
.\LlmPwManager.exe credential-status bastion-deploy --profile limited
.\LlmPwManager.exe validate-config
.\LlmPwManager.exe doctor
.\LlmPwManager.exe status --profile limited
.\LlmPwManager.exe audit-tail --limit 20 --profile limited
.\LlmPwManager.exe mcp-config --format mcpServers --profile limited
.\LlmPwManager.exe policy-check --tool ssh_run --route prod-route --command "systemctl status nginx --no-pager" --profile limited
.\LlmPwManager.exe add-client-profile --id claude-desktop --permission limited --tools "ssh_run,ssh_register,ssh_open_session,session_list,session_close,db_query,db_register,browser_login,browser_register,route_test,policy_check,credential_status,forget_credential,config_summary,audit_tail" --confirm-local-management true
.\LlmPwManager.exe set-default-profile --id claude-desktop --confirm-local-management true
.\LlmPwManager.exe set-session-timeout --minutes 15 --confirm-local-management true
.\LlmPwManager.exe add-credential --alias prod-deploy --user deploy --label "Prod deploy password" --confirm-local-management true
.\LlmPwManager.exe add-ssh-target --id prod --host prod.example.com --user deploy --credential prod-deploy --confirm-local-management true
.\LlmPwManager.exe add-route --id prod-route --chain prod --confirm-local-management true
.\LlmPwManager.exe add-ssh-policy --id read-prod --routes prod-route --prefixes "df,uptime,systemctl status" --confirm-local-management true
.\LlmPwManager.exe route-test bastion --profile limited
.\LlmPwManager.exe ssh-run bastion "systemctl status nginx --no-pager" --profile limited
.\LlmPwManager.exe db-query payments-db-via-bastion "select count(*) from payment_logs" --profile limited
.\LlmPwManager.exe db-query payments-db-via-bastion "select * from payment_logs where id = @id" --param id=123 --profile limited
.\LlmPwManager.exe forget-credential bastion-deploy --profile limited
```

The CLI uses the same Credential Manager, password prompt, policy checks, approval dialog, SSH route handling, DB drivers, redaction, and audit log as the MCP server.

Reusable SSH sessions are MCP-only because they live inside the running broker process. CLI calls are one-shot commands.

`status` and `list` print a profile-scoped config summary when the selected profile allows `config_summary`. `full` profiles receive detailed non-secret management metadata. Non-full profiles receive a minimal summary: allowed tools, credential status counts, route IDs with hop counts, DB target IDs, browser target IDs, and policy count. Minimal summaries intentionally hide SSH hosts, user names, credential aliases, route chains, browser selectors, login URLs, and policy command prefixes. `validate-config` reports config errors as JSON and can be used before connecting an LLM client. It also catches misspelled tool names in client profiles and policy rules, duplicate policy IDs, and references to unknown routes, targets, or credential aliases.

`doctor` prints a secret-free readiness report. It validates config, reports credential aliases as `registered` or `missing`, checks limited-profile policy coverage for SSH/DB/browser targets, checks whether Microsoft Edge is available for managed browser targets, includes generated MCP stdio config, and shows config/audit paths.

The `add-*` and `set-*` commands only write non-secret config. They register aliases, targets, routes, DB metadata, and policy rules, but never accept a password on the command line. Because these are local management operations, they require `--confirm-local-management true`; normal MCP tool calls cannot mutate config. The first `route-test`, `ssh-run`, `db-query`, or `browser-login` that needs a missing credential opens the native Windows prompt, tests the credential, and stores it through Windows Credential Manager.

Config identifiers such as credential aliases, profile IDs, route IDs, target IDs, and policy IDs may contain only letters, numbers, `.`, `_`, and `-`, up to 128 characters. Labels and user names are separate fields and can be more descriptive.

## Configuration

The app creates a sample non-secret config at:

```powershell
.\LlmPwManager.exe config-path
```

By default this lives under `%APPDATA%\LlmPwManager`. For portable or test runs, set `LLM_PW_MANAGER_HOME` to override the config/audit directory:

```powershell
$env:LLM_PW_MANAGER_HOME = "D:\portable\llm-pw-manager"
.\LlmPwManager.exe config-path
```

The config contains:

- client profiles
- `sessionIdleTimeoutMinutes` for broker-held SSH sessions
- credential aliases
- SSH targets
- route chains
- DB targets
- browser targets
- policy rules

Secrets are not stored in this file. They are stored in Windows Credential Manager under broker-owned keys.

The broker validates config on startup. It fails fast for missing route references, unknown credential aliases, duplicate IDs, invalid ports, empty route chains, and DB targets pointing at missing SSH routes.

Change SSH session idle timeout without editing JSON:

```powershell
.\LlmPwManager.exe set-session-timeout --minutes 15 --confirm-local-management true
```

To reset the sample config:

```powershell
.\LlmPwManager.exe init-sample --force
```

### Setup Example

```powershell
.\LlmPwManager.exe add-credential --alias bastion-deploy --user deploy --label "Bastion deploy password" --confirm-local-management true
.\LlmPwManager.exe add-ssh-target --id bastion --host bastion.example.com --port 22 --user deploy --credential bastion-deploy --confirm-local-management true
.\LlmPwManager.exe add-route --id bastion --chain bastion --confirm-local-management true
.\LlmPwManager.exe add-ssh-policy --id read-bastion --routes bastion --prefixes "df,uptime,systemctl status,hostname" --confirm-local-management true
.\LlmPwManager.exe validate-config
.\LlmPwManager.exe route-test bastion --profile limited
```

If an SSH address is not registered yet, an MCP client can call `ssh_register`
instead of failing silently. The broker first shows a native Windows approval
dialog with the requested host, port, user, and purpose. If the local user
approves, the broker opens the native password prompt, tests the SSH login, and
stores the password only after the test succeeds:

```json
{
  "name": "ssh_register",
  "arguments": {
    "route_id": "prod-bastion",
    "host": "prod.example.com",
    "port": 22,
    "user_name": "deploy",
    "purpose": "register SSH access for deployment checks",
    "command_prefixes": ["uptime", "df", "systemctl status"],
    "client_profile": "limited"
  }
}
```

This creates a direct SSH target, route, credential alias, and limited SSH
policy for the supplied command prefixes. The LLM sees only the resulting route
metadata; it never sees the password.

For a DB reachable through that SSH route:

```powershell
.\LlmPwManager.exe add-credential --alias payments-db-readonly --user readonly --label "Payments DB readonly password" --confirm-local-management true
.\LlmPwManager.exe add-db-target --id payments-db-via-bastion --engine postgres --host 10.30.0.20 --port 5432 --database payments --user readonly --credential payments-db-readonly --route bastion --max-rows 50 --confirm-local-management true
.\LlmPwManager.exe add-db-policy --id read-payments --connections payments-db-via-bastion --confirm-local-management true
.\LlmPwManager.exe db-query payments-db-via-bastion "select count(*) from payment_logs" --profile limited
```

If a DB connection is not registered yet, an MCP client can call `db_register`.
The broker shows a native approval dialog, asks for the DB password locally,
tests the connection with `select 1`, and stores the password only after the
test succeeds:

```json
{
  "name": "db_register",
  "arguments": {
    "connection_id": "payments-db",
    "engine": "postgres",
    "host": "10.30.0.20",
    "port": 5432,
    "database": "payments",
    "user_name": "readonly",
    "route_id": "bastion",
    "purpose": "register readonly payments DB access",
    "client_profile": "limited"
  }
}
```

If `route_id` is set, that SSH route must already be registered. For a DB on a
new private network path, register the SSH route first with `ssh_register`, then
call `db_register`.

### Nested SSH To DB Example

Routes can contain more than one SSH hop, and DB targets can use those routes.
This supports private network paths such as:

```text
local Windows broker -> outer SSH -> inner SSH -> DB on inner host
```

Each hop uses its own credential alias, and the DB uses a separate credential
alias. If all three secrets are missing, the first query opens native Windows
password prompts in connection order:

1. Outer SSH password.
2. Inner SSH password.
3. DB password.

Only the local prompt sees the password text. The LLM sees route IDs, DB target
IDs, redacted results, and `secret_visible_to_model: false`.

Example non-secret setup:

```powershell
.\LlmPwManager.exe add-credential --alias outer-ssh-password --user outeruser --label "Outer SSH password" --confirm-local-management true
.\LlmPwManager.exe add-ssh-target --id outer-ssh --host 203.0.113.10 --port 22 --user outeruser --credential outer-ssh-password --confirm-local-management true

.\LlmPwManager.exe add-credential --alias inner-ssh-password --user inneruser --label "Inner SSH password" --confirm-local-management true
.\LlmPwManager.exe add-ssh-target --id inner-ssh --host inner-host.private --port 22 --user inneruser --credential inner-ssh-password --confirm-local-management true

.\LlmPwManager.exe add-route --id outer-inner-route --chain "outer-ssh,inner-ssh" --confirm-local-management true
.\LlmPwManager.exe add-ssh-policy --id outer-inner-read --routes outer-inner-route --prefixes "whoami,hostname" --confirm-local-management true

.\LlmPwManager.exe add-credential --alias inner-db-password --user dbuser --label "Inner DB password" --confirm-local-management true
.\LlmPwManager.exe add-db-target --id inner-db --engine mysql --host 127.0.0.1 --port 3306 --database appdb --user dbuser --credential inner-db-password --route outer-inner-route --max-rows 10 --confirm-local-management true
.\LlmPwManager.exe add-db-policy --id inner-db-read --connections inner-db --confirm-local-management true
```

Run the query through both SSH hops:

```powershell
.\LlmPwManager.exe db-query inner-db "select value from healthcheck where name = 'path'" --profile limited
```

This scenario was verified with Podman-backed test containers on WSL:

```text
Windows broker -> outer SSH -> inner SSH -> MariaDB on 127.0.0.1:3306
```

The successful broker response returned the DB value and kept all three
credentials isolated:

```json
{
  "ok": true,
  "connection_id": "inner-db-through-two-ssh",
  "rows": [
    {
      "value": "outer-inner-db-ok"
    }
  ],
  "secret_visible_to_model": false
}
```

For a browser login target:

```powershell
.\LlmPwManager.exe add-credential --alias admin-console-password --user operator@example.com --label "Admin console password" --confirm-local-management true
.\LlmPwManager.exe add-browser-target --id admin-console --url https://admin.example.com/login --user operator@example.com --credential admin-console-password --user-selector "#email" --password-selector "#password" --submit-selector "button[type=submit]" --success-url-contains "/dashboard" --failure-selector ".login-error" --confirm-local-management true
.\LlmPwManager.exe add-browser-policy --id login-admin-console --targets admin-console --confirm-local-management true
.\LlmPwManager.exe browser-login admin-console --profile limited
```

If a browser login target is not registered yet, an MCP client can call
`browser_register`. The broker shows a native approval dialog, opens an isolated
Edge profile, asks for the password locally, fills only the configured selectors,
and stores the password only after the success condition is observed:

```json
{
  "name": "browser_register",
  "arguments": {
    "target_id": "admin-console",
    "login_url": "https://admin.example.com/login",
    "user_name": "operator@example.com",
    "user_name_selector": "#email",
    "password_selector": "#password",
    "submit_selector": "button[type=submit]",
    "success_url_contains": "/dashboard",
    "failure_selector": ".login-error",
    "purpose": "register admin console login",
    "client_profile": "limited"
  }
}
```

### SSH Auth Modes

Password authentication:

```json
{
  "id": "bastion",
  "host": "bastion.example.com",
  "port": 22,
  "userName": "deploy",
  "authMode": "Password",
  "credentialAlias": "bastion-deploy"
}
```

Private key without passphrase:

```json
{
  "id": "bastion-key",
  "host": "bastion.example.com",
  "port": 22,
  "userName": "deploy",
  "authMode": "PrivateKey",
  "privateKeyPath": "%USERPROFILE%\\.ssh\\id_ed25519"
}
```

Private key with passphrase stored through the broker:

```json
{
  "id": "bastion-key",
  "host": "bastion.example.com",
  "port": 22,
  "userName": "deploy",
  "authMode": "PrivateKey",
  "privateKeyPath": "%USERPROFILE%\\.ssh\\id_ed25519",
  "credentialAlias": "bastion-key-passphrase"
}
```

For passphrase-protected keys, the LLM still never receives the passphrase. The native prompt and connection test flow is the same as password authentication.

SSH stdout and stderr are redacted before they are returned. The broker removes known broker-held secrets and also masks secret-like patterns such as `password=...`, `token=...`, `api_key=...`, `access_key=...`, `private_key=...`, `credential=...`, and URI userinfo.

## Reusable SSH Sessions

For multi-step work over the same SSH chain, an MCP client can open a broker-held session once and then refer to it by opaque `session_id`:

```json
{
  "name": "ssh_open_session",
  "arguments": {
    "route_id": "bastion-to-app-02",
    "purpose": "inspect nginx status and recent logs",
    "client_profile": "limited"
  }
}
```

The response contains metadata such as:

```json
{
  "session_id": "ssh_1f6d...",
  "route_id": "bastion-to-app-02",
  "client_profile": "limited",
  "secret_visible_to_model": false
}
```

Subsequent commands can use the session without reconnecting through each hop:

```json
{
  "name": "ssh_run",
  "arguments": {
    "session_id": "ssh_1f6d...",
    "command": "systemctl status nginx --no-pager",
    "purpose": "check service health",
    "client_profile": "limited"
  }
}
```

The broker still evaluates `ssh_run` policy for every command using the session route. `session_list` returns active session metadata only, including `expiresAt`, and `session_close` tears down the SSH clients and local forwards. Idle sessions expire automatically after `sessionIdleTimeoutMinutes` in config; the default is 30 minutes.

Reusable sessions are scoped to the `client_profile` that opened them. Other profiles cannot list, reuse, or close that session even if they learn the opaque `session_id`.

The same session can also be reused for a DB target configured with the same `routeId`:

```json
{
  "name": "db_query",
  "arguments": {
    "connection_id": "payments-db-via-bastion",
    "session_id": "ssh_1f6d...",
    "sql": "select count(*) from payment_logs",
    "purpose": "check payment log volume",
    "client_profile": "limited"
  }
}
```

`db_query` still evaluates the DB policy for every query. If the DB target is not configured for SSH routing, or if its route does not match the supplied SSH session route, the broker rejects the call without trying to connect.

DB result values in clearly secret-like columns such as `password`, `password_hash`, `token`, `api_key`, `secret`, `access_key`, and `private_key` are returned as `[REDACTED]`. String values in other columns are also scanned for secret-like assignments and URI userinfo, so values such as `token=...` or `postgres://user:pass@host` are masked without hiding the whole column. Responses include `redacted_columns` and `secret_visible_to_model: false` so the LLM can explain that sensitive fields were intentionally hidden.

DB responses set `truncated: true` only after the broker reads one additional row beyond the configured `maxRows`, so an exact `maxRows` result is not reported as truncated.

## Browser Login

Browser login is intentionally narrow. The broker opens Microsoft Edge with a broker-owned isolated run profile under the app data directory, connects to that Edge instance through the local DevTools endpoint, and fills only the configured username/password/submit selectors. After login verification, the broker closes the Edge process it started and makes a best-effort attempt to delete that one-time run profile. The LLM receives only a status result; it never receives the password, the form value, cookies, or a DOM dump.

Limited and approval profiles require a matching browser policy:

```powershell
.\LlmPwManager.exe add-browser-policy --id login-admin-console --targets admin-console --min-permission limited --confirm-local-management true
```

MCP example:

```json
{
  "name": "browser_login",
  "arguments": {
    "target_id": "admin-console",
    "purpose": "open authenticated admin console for operator review",
    "client_profile": "limited"
  }
}
```

For `ManagedProfile` browser targets, config must include:

- `userNameSelector`
- `passwordSelector`
- `submitSelector`
- either `successSelector` or `successUrlContains`

If the password is missing or fails the configured success check, the native Windows password prompt is shown and the candidate is retried. A password is stored only after the configured success condition is observed. Sites with MFA, SSO redirects, CAPTCHA, or unusual login flows may need the user to finish the flow in the visible Edge window; the broker still will not expose the password to the LLM.

When the configured success condition is not observed, the broker makes a best-effort attempt to clear the configured password field before asking again.

## Credential Flow

When a tool needs a credential:

1. The broker checks Windows Credential Manager.
2. If missing, a native Windows password dialog appears outside the LLM conversation.
3. The broker tests the password by connecting to the SSH host, DB, or configured browser login.
4. If the test succeeds, the broker saves the secret and continues the original tool call.
5. If the test fails, the broker asks again up to three attempts and shows the user a safe, redacted failure reason when one is available.
6. The LLM only receives a safe status or task result.

To rotate or repair a saved credential, forget it by alias:

```powershell
.\LlmPwManager.exe forget-credential bastion-deploy
```

The command deletes the stored Windows Credential Manager entry but does not remove the non-secret alias from config. The next `route-test`, `ssh-run`, or `db-query` that needs that alias opens the native Windows prompt and stores the newly tested credential. MCP clients can call `forget_credential` when their client profile allows it.

Credential status and forget operations are limited to credential aliases declared in config. Unknown aliases return `unknown` and do not query or delete Windows Credential Manager entries. MCP/CLI responses and audit records also avoid echoing unknown aliases, unknown tool names, and missing session IDs back to the model.

## Permission Profiles

LLM clients are configured with broker-side profiles, so the product is not tied to Codex, Claude, Cursor, or any specific agent.

- `full`: runs configured tools without extra approval.
- `limited`: allows only policy-matched safe SSH commands and read-style DB queries.
- `approval`: asks with a Windows approval dialog when policy requires it.
- `deny-by-default`: blocks everything except explicitly allowed behavior.

Normal tool calls do not trigger user prompts by themselves. Prompts appear only for missing/failed credentials, policy-required approval, or explicit onboarding tools such as `ssh_register`, `db_register`, and `browser_register`.

To avoid unnecessary approval prompts or failed tool calls, clients can check policy without executing the operation:

```powershell
.\LlmPwManager.exe policy-check --tool ssh_run --route bastion --command "uptime" --profile limited
.\LlmPwManager.exe policy-check --tool db_query --connection payments-db-via-bastion --sql "select count(*) from payment_logs" --profile limited
.\LlmPwManager.exe policy-check --tool browser_login --target admin-console --profile limited
```

MCP clients can call `policy_check` with the same fields. The check never opens a password prompt or approval dialog; it returns `allowed`, `needs_approval`, and `reason`.

When an approval-profile client approves the exact same profile/target/action/reason combination, the broker remembers that approval in memory for the current process session. It does not persist approval cache entries to disk, and restarting the broker clears the cache.

Create a client-specific profile:

```powershell
.\LlmPwManager.exe add-client-profile --id claude-desktop --permission limited --tools "ssh_run,ssh_register,ssh_open_session,session_list,session_close,db_query,db_register,browser_login,browser_register,route_test,policy_check,credential_status,forget_credential,config_summary,audit_tail" --confirm-local-management true
.\LlmPwManager.exe add-client-profile --id local-agent --permission approval --tools "ssh_run,ssh_register,ssh_open_session,session_list,session_close,db_query,db_register,browser_login,browser_register,route_test,policy_check,credential_status,forget_credential,config_summary,audit_tail" --confirm-local-management true
.\LlmPwManager.exe set-default-profile --id claude-desktop --confirm-local-management true
```

MCP server processes are locked to one client profile through `LLM_PW_MANAGER_CLIENT_PROFILE`. If that environment variable is omitted, the server is locked to `defaultClientProfile`; the generated sample config starts with `limited` as the default. `mcp-config --profile <id>` validates that the profile exists before emitting client configuration. MCP clients may omit `client_profile`, or pass the same locked profile for compatibility. If a model tries to pass a different profile such as `full`, the broker denies the call before policy evaluation. CLI commands still accept `--profile` because they are local user commands rather than model-controlled MCP calls; unknown CLI profiles are denied as `unknown_client_profile` without echoing the provided profile string.

`tools/list` is profile-scoped, so an MCP client only sees tools allowed by the locked client profile. MCP metadata tools such as `credential_status`, `config_summary`, and `audit_tail` also respect the profile's allowed tool list. They never return secret values. `config_summary` is profile-scoped: non-full MCP clients see the minimal summary described above, while `full` clients can see detailed management metadata.

For SSH, non-full policy rules that allow `ssh_run` must define `commandPrefixes`. Limited policy rules reject shell operators such as `;`, `&&`, `|`, redirects, backticks, and command substitution unless a rule explicitly sets `allowShellOperators` to `true`. This prevents a safe-looking prefix such as `df -h` from becoming `df -h; destructive-command`.

For DB queries, limited read-only policy allows only one read-style statement. Multi-statement SQL and write keywords such as `insert`, `update`, `delete`, `drop`, and `truncate` are denied unless the policy explicitly allows write SQL.

## Audit Log

The broker writes a secret-free JSONL audit log next to the config:

```text
%APPDATA%\LlmPwManager\audit.jsonl
```

Audit entries include tool name, profile, target, safe action summary, status, reason, and timestamp. They do not include passwords, tokens, private keys, credentials, or connection strings. Before writing, the broker also redacts secret-like assignments such as `password=...`, `token=...`, `api_key=...`, `access_key=...`, `private_key=...`, `credential=...`, and URI userinfo such as `postgres://user:pass@host`.

Tool and CLI failures also avoid returning raw exception messages. MCP responses and CLI JSON use stable error codes plus generic safe messages, so driver errors cannot accidentally echo a password, passphrase, token, or connection string back to the LLM. Malformed MCP frames, unknown JSON-RPC methods, and unknown tool names are returned as generic errors instead of crashing the broker or echoing request text.

Read recent audit entries:

```powershell
.\LlmPwManager.exe audit-tail --limit 20
```

MCP clients can call `audit_tail` when their client profile allows it. Audit entries are designed to be secret-free, but they may contain operational metadata such as route IDs, DB IDs, and safe action summaries.

## Security Boundary

The LLM must use broker tools instead of directly running password-prompting clients such as:

```text
ssh
mysql -p
psql
```

Complex routes are handled inside the broker:

```text
local Windows -> bastion SSH -> internal SSH -> DB
```

The LLM sees route IDs, session results, redacted stdout/stderr, and DB rows. It never sees decrypted credentials.

## Browser Boundary

The browser MVP is a login adapter, not a general browser automation API. It does not provide tools to read arbitrary page content, inspect password fields, export cookies, or run model-supplied JavaScript. Future browser expansion should keep that boundary: high-level broker-owned actions, isolated profiles, and no credential or session material returned to the LLM.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

Third-party runtime and test dependency license metadata is summarized in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

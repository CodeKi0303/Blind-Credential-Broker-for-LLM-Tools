using System.Text.Json;
using System.Globalization;
using LlmPwManager.Audit;
using LlmPwManager.Browser;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Db;
using LlmPwManager.Mcp;
using LlmPwManager.Policy;
using LlmPwManager.Routing;
using LlmPwManager.Security;
using LlmPwManager.Ssh;
using LlmPwManager.Ui;

namespace LlmPwManager.App;

internal static class AppHost
{
    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        var appDirectory = AppPaths.EnsureAppDirectory();
        var configPath = Path.Combine(appDirectory, "config.json");

        if (args.Length > 0 && args[0].Equals("init-sample", StringComparison.OrdinalIgnoreCase))
        {
            AppConfigStore.WriteSample(configPath, overwrite: args.Contains("--force"));
            Console.WriteLine($"sample config written: {configPath}");
            return 0;
        }

        if (args.Length > 0 && args[0].Equals("config-path", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine(configPath);
            return 0;
        }

        var config = AppConfigStore.LoadOrCreate(configPath);

        if (args.Length > 0 && args[0].Equals("mcp-config", StringComparison.OrdinalIgnoreCase))
        {
            var options = ParseOptions(args[1..]);
            var includeHome = OptionalBool(options, "include-home", true);
            var profile = Optional(options, "profile");
            if (!string.IsNullOrWhiteSpace(profile) && !IsConfiguredClientProfile(config, profile))
            {
                WriteJson(new
                {
                    ok = false,
                    code = "unknown_client_profile",
                    safe_message = "The requested MCP client profile is not configured."
                });
                return 2;
            }

            WriteJson(McpClientConfigFactory.Create(
                Optional(options, "format") ?? "generic",
                Optional(options, "name") ?? "llm-pw-manager",
                includeHome ? appDirectory : null,
                profile));
            return 0;
        }

        if (args.Length > 0 && args[0].Equals("validate-config", StringComparison.OrdinalIgnoreCase))
        {
            var errors = ConfigErrorSanitizer.Sanitize(AppConfigValidator.Validate(config));
            WriteJson(new { ok = errors.Count == 0, errors });
            return errors.Count == 0 ? 0 : 2;
        }

        if (args.Length > 0 && IsConfigMutationCommand(args[0]))
        {
            return RunConfigMutation(configPath, config, args);
        }

        var credentialStore = new WindowsCredentialStore("llm-pw-manager");
        var auditPath = Path.Combine(appDirectory, "audit.jsonl");

        if (args.Length > 0 && args[0].Equals("doctor", StringComparison.OrdinalIgnoreCase))
        {
            WriteJson(DoctorReport.Build(config, credentialStore, configPath, auditPath, appDirectory));
            return 0;
        }

        AppConfigValidator.ThrowIfInvalid(config);

        var prompt = new WindowsCredentialPrompt();
        var approvalPrompt = new WindowsApprovalPrompt();
        var audit = new AuditLogger(auditPath);
        var auditReader = new AuditLogReader(auditPath);
        var resolver = new CredentialResolver(credentialStore, prompt, maxAttempts: 3);
        var policy = new PolicyEvaluator(config);
        var approvalCache = new ApprovalCache();
        var router = new RouteResolver(config);
        var redactor = new SecretRedactor();
        var ssh = new SshExecutor(config, router, resolver, redactor);
        using var sshSessions = new SshSessionManager(ssh, TimeSpan.FromMinutes(config.SessionIdleTimeoutMinutes));
        var db = new DbExecutor(config, router, resolver, ssh, redactor);
        var browser = new ManagedEdgeBrowserLoginExecutor(config, resolver, appDirectory);
        var summary = new ConfigSummary(config, credentialStore);
        var sshRegistration = new SshRegistrationService(config, configPath, resolver);
        var dbRegistration = new DbRegistrationService(config, configPath, db, resolver);
        var browserRegistration = new BrowserRegistrationService(config, configPath, browser, resolver);

        if (args.Length == 0 || args[0].Equals("mcp", StringComparison.OrdinalIgnoreCase))
        {
            string mcpClientProfile;
            try
            {
                mcpClientProfile = ResolveMcpClientProfile(config);
            }
            catch (InvalidOperationException)
            {
                Console.Error.WriteLine("MCP client profile is not configured.");
                return 2;
            }

            var tools = new ToolRegistry(config, policy, approvalPrompt, approvalCache, audit, auditReader, resolver, ssh, sshSessions, db, browser, summary, mcpClientProfile, sshRegistration, dbRegistration, browserRegistration);
            await new McpServer(tools).RunAsync(Console.OpenStandardInput(), Console.OpenStandardOutput(), cancellationToken);
            return 0;
        }

        if (args[0].Equals("credential-status", StringComparison.OrdinalIgnoreCase) && args.Length >= 2)
        {
            var parsed = ParseProfile(args[2..], config.DefaultClientProfile);
            if (!IsConfiguredClientProfile(config, parsed.Profile))
            {
                return DenyUnknownClientProfile(audit, "credential_status", "read credential status");
            }

            if (!IsToolAllowedForProfile(config, "credential_status", parsed.Profile))
            {
                audit.Record("credential_status", parsed.Profile, "credential", "read credential status", "denied", "tool is not allowed for this client profile");
                WriteJson(new { ok = false, code = "policy_denied", reason = "tool is not allowed for this client profile", needsApproval = false });
                return 3;
            }

            if (!IsConfiguredCredentialAlias(config, args[1]))
            {
                audit.Record("credential_status", parsed.Profile, "credential", "read unknown credential status", "unknown", "credential alias is not configured");
                WriteJson(new
                {
                    ok = true,
                    status = "unknown",
                    configured = false,
                    secret_visible_to_model = false
                });
                return 0;
            }

            WriteJson(new
            {
                ok = true,
                alias = args[1],
                status = credentialStore.Exists(args[1]) ? "registered" : "missing",
                configured = true,
                secret_visible_to_model = false
            });
            return 0;
        }

        if (args[0].Equals("forget-credential", StringComparison.OrdinalIgnoreCase) && args.Length >= 2)
        {
            var parsed = ParseProfile(args[2..], config.DefaultClientProfile);
            var alias = args[1];
            if (!IsConfiguredClientProfile(config, parsed.Profile))
            {
                return DenyUnknownClientProfile(audit, "forget_credential", "delete credential alias");
            }

            if (!IsToolAllowedForProfile(config, "forget_credential", parsed.Profile))
            {
                audit.Record("forget_credential", parsed.Profile, "credential", "delete credential alias", "denied", "tool is not allowed for this client profile");
                WriteJson(new { ok = false, code = "policy_denied", reason = "tool is not allowed for this client profile", needsApproval = false });
                return 3;
            }

            if (!IsConfiguredCredentialAlias(config, alias))
            {
                audit.Record("forget_credential", parsed.Profile, "credential", "delete unknown credential alias", "unknown", "credential alias is not configured");
                WriteJson(new
                {
                    ok = true,
                    status = "unknown",
                    configured = false,
                    secret_visible_to_model = false
                });
                return 0;
            }

            var existed = credentialStore.Exists(alias);
            credentialStore.DeleteSecret(alias);
            audit.Record("forget_credential", parsed.Profile, alias, "delete credential alias", existed ? "forgotten" : "missing");
            WriteJson(new
            {
                ok = true,
                alias,
                status = existed ? "forgotten" : "missing",
                configured = true,
                secret_visible_to_model = false
            });
            return 0;
        }

        if (args[0].Equals("status", StringComparison.OrdinalIgnoreCase) ||
            args[0].Equals("list", StringComparison.OrdinalIgnoreCase))
        {
            var parsed = ParseProfile(args[1..], config.DefaultClientProfile);
            if (!IsConfiguredClientProfile(config, parsed.Profile))
            {
                return DenyUnknownClientProfile(audit, "config_summary", "read config summary");
            }

            if (!IsToolAllowedForProfile(config, "config_summary", parsed.Profile))
            {
                audit.Record("config_summary", parsed.Profile, "config", "read config summary", "denied", "tool is not allowed for this client profile");
                WriteJson(new { ok = false, code = "policy_denied", reason = "tool is not allowed for this client profile", needsApproval = false });
                return 3;
            }

            WriteJson(new
            {
                ok = true,
                config_path = configPath,
                audit_path = Path.Combine(appDirectory, "audit.jsonl"),
                summary = summary.Build(parsed.Profile)
            });
            return 0;
        }

        if (args[0].Equals("audit-tail", StringComparison.OrdinalIgnoreCase))
        {
            var options = ParseOptions(args[1..]);
            var profile = Optional(options, "profile") ?? config.DefaultClientProfile;
            if (!IsConfiguredClientProfile(config, profile))
            {
                return DenyUnknownClientProfile(audit, "audit_tail", "read audit tail");
            }

            if (!IsToolAllowedForProfile(config, "audit_tail", profile))
            {
                audit.Record("audit_tail", profile, "audit", "read audit tail", "denied", "tool is not allowed for this client profile");
                WriteJson(new { ok = false, code = "policy_denied", reason = "tool is not allowed for this client profile", needsApproval = false });
                return 3;
            }

            var limit = OptionalInt(options, "limit", 20);
            WriteJson(new
            {
                ok = true,
                audit_path = auditPath,
                entries = auditReader.Tail(limit)
            });
            return 0;
        }

        if (args[0].Equals("policy-check", StringComparison.OrdinalIgnoreCase))
        {
            var options = ParseOptions(args[1..]);
            var profile = Optional(options, "profile") ?? config.DefaultClientProfile;
            if (!IsConfiguredClientProfile(config, profile))
            {
                return DenyUnknownClientProfile(audit, "policy_check", "check policy");
            }

            var requestedTool = NormalizeToolName(Required(options, "tool"));
            var decision = EvaluatePolicyCheck(
                policy,
                config,
                requestedTool,
                profile,
                Optional(options, "route"),
                Optional(options, "connection"),
                Optional(options, "target"),
                Optional(options, "command") ?? "",
                Optional(options, "sql") ?? "");
            WriteJson(new
            {
                ok = true,
                tool_name = IsKnownTool(requestedTool) ? requestedTool : "unknown",
                client_profile = profile,
                allowed = decision.Allowed,
                needs_approval = decision.NeedsApproval,
                reason = decision.Reason,
                prompt_shown = false,
                secret_visible_to_model = false
            });
            return 0;
        }

        if (args[0].Equals("ssh-run", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
        {
            return await RunCliToolAsync(async () =>
            {
                var parsed = ParseProfile(args[2..], config.DefaultClientProfile);
                var routeId = args[1];
                var command = string.Join(' ', parsed.Args);
                if (!IsConfiguredClientProfile(config, parsed.Profile))
                {
                    return DenyUnknownClientProfile(audit, "ssh_run", "run SSH command");
                }

                var decision = policy.Evaluate(new ToolRequest("ssh_run", parsed.Profile, RouteId: routeId, Command: command));
                if (!EnsureAllowed(approvalPrompt, approvalCache, decision, parsed.Profile, "SSH command approval required", routeId, command))
                {
                    audit.Record("ssh_run", parsed.Profile, routeId, SafeAction(command), "denied", decision.Reason);
                    WriteJson(new { ok = false, code = "policy_denied", decision.Reason, decision.NeedsApproval });
                    return 3;
                }

                var result = await ssh.RunCommandAsync(routeId, command, cancellationToken);
                audit.Record("ssh_run", parsed.Profile, routeId, SafeAction(command), "ok");
                WriteJson(new
                {
                    ok = true,
                    route_id = routeId,
                    exit_status = result.ExitStatus,
                    stdout = result.Stdout,
                    stderr = result.Stderr,
                    secret_visible_to_model = false
                });
                return result.ExitStatus == 0 ? 0 : result.ExitStatus;
            });
        }

        if (args[0].Equals("db-query", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
        {
            return await RunCliToolAsync(async () =>
            {
                var parsed = ParseProfile(args[2..], config.DefaultClientProfile);
                var connectionId = args[1];
                var dbArgs = ParseDbArgs(parsed.Args);
                var sql = string.Join(' ', dbArgs.SqlParts);
                if (!IsConfiguredClientProfile(config, parsed.Profile))
                {
                    return DenyUnknownClientProfile(audit, "db_query", "run DB query");
                }

                var decision = policy.Evaluate(new ToolRequest("db_query", parsed.Profile, ConnectionId: connectionId, Sql: sql));
                if (!EnsureAllowed(approvalPrompt, approvalCache, decision, parsed.Profile, "DB query approval required", connectionId, sql))
                {
                    audit.Record("db_query", parsed.Profile, connectionId, SafeAction(sql), "denied", decision.Reason);
                    WriteJson(new { ok = false, code = "policy_denied", decision.Reason, decision.NeedsApproval });
                    return 3;
                }

                var result = await db.QueryAsync(connectionId, sql, dbArgs.Parameters, cancellationToken);
                audit.Record("db_query", parsed.Profile, connectionId, SafeAction(sql), "ok");
                WriteJson(new
                {
                    ok = true,
                    connection_id = connectionId,
                    result.Columns,
                    result.Rows,
                    result.Truncated,
                    redacted_columns = result.RedactedColumns,
                    secret_visible_to_model = false
                });
                return 0;
            });
        }

        if (args[0].Equals("route-test", StringComparison.OrdinalIgnoreCase) && args.Length >= 2)
        {
            return await RunCliToolAsync(async () =>
            {
                var parsed = ParseProfile(args[2..], config.DefaultClientProfile);
                var routeId = args[1];
                if (!IsConfiguredClientProfile(config, parsed.Profile))
                {
                    return DenyUnknownClientProfile(audit, "route_test", "test route connectivity");
                }

                var decision = policy.Evaluate(new ToolRequest("route_test", parsed.Profile, RouteId: routeId));
                if (!EnsureAllowed(approvalPrompt, approvalCache, decision, parsed.Profile, "Route test approval required", routeId, "test route connectivity"))
                {
                    audit.Record("route_test", parsed.Profile, routeId, "test route connectivity", "denied", decision.Reason);
                    WriteJson(new { ok = false, code = "policy_denied", decision.Reason, decision.NeedsApproval });
                    return 3;
                }

                using var route = await ssh.ConnectRouteAsync(routeId, cancellationToken);
                audit.Record("route_test", parsed.Profile, routeId, "test route connectivity", "ok");
                WriteJson(new { ok = true, route_id = routeId, status = "ok" });
                return 0;
            });
        }

        if (args[0].Equals("browser-login", StringComparison.OrdinalIgnoreCase) && args.Length >= 2)
        {
            return await RunCliToolAsync(async () =>
            {
                var parsed = ParseProfile(args[2..], config.DefaultClientProfile);
                var targetId = args[1];
                if (!IsConfiguredClientProfile(config, parsed.Profile))
                {
                    return DenyUnknownClientProfile(audit, "browser_login", "browser login");
                }

                var target = config.BrowserTargets.FirstOrDefault(browserTarget =>
                    browserTarget.Id.Equals(targetId, StringComparison.OrdinalIgnoreCase))
                    ?? throw new InvalidOperationException($"Unknown browser target: {targetId}");
                var decision = policy.Evaluate(new ToolRequest("browser_login", parsed.Profile, BrowserTargetId: targetId));
                if (!EnsureAllowed(approvalPrompt, approvalCache, decision, parsed.Profile, "Browser login approval required", targetId, "browser login"))
                {
                    audit.Record("browser_login", parsed.Profile, targetId, "browser login", "denied", decision.Reason);
                    WriteJson(new { ok = false, code = "policy_denied", decision.Reason, decision.NeedsApproval });
                    return 3;
                }

                var result = await browser.LoginAsync(target, cancellationToken);
                audit.Record("browser_login", parsed.Profile, targetId, "browser login", result.Success ? "ok" : result.Status, result.SafeMessage);
                WriteJson(new
                {
                    ok = result.Success,
                    target_id = targetId,
                    status = result.Status,
                    safe_message = result.SafeMessage,
                    secret_visible_to_model = false
                });
                return result.Success ? 0 : 5;
            });
        }

        Console.Error.WriteLine("usage: LlmPwManager [mcp|mcp-config|doctor|init-sample|config-path|validate-config|status|list|audit-tail|policy-check|add-client-profile|set-default-profile|set-session-timeout|add-credential|add-ssh-target|add-route|add-db-target|add-browser-target|add-ssh-policy|add-db-policy|add-browser-policy|credential-status <alias>|forget-credential <alias>|ssh-run <route> <command...>|db-query <connection> <sql...>|route-test <route>|browser-login <target>]");
        return 2;
    }

    private static bool IsConfigMutationCommand(string command)
    {
        return command.Equals("add-credential", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-client-profile", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("set-default-profile", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("set-session-timeout", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-ssh-target", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-route", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-db-target", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-browser-target", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-ssh-policy", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-db-policy", StringComparison.OrdinalIgnoreCase) ||
            command.Equals("add-browser-policy", StringComparison.OrdinalIgnoreCase);
    }

    private static int RunConfigMutation(string configPath, AppConfig config, string[] args)
    {
        try
        {
            var command = args[0].ToLowerInvariant();
            var options = ParseOptions(args[1..]);
            if (!OptionalBool(options, "confirm-local-management", false))
            {
                WriteJson(new
                {
                    ok = false,
                    code = "management_confirmation_required",
                    safe_message = "Config mutation commands require --confirm-local-management true."
                });
                return 3;
            }

            switch (command)
            {
                case "add-client-profile":
                    ConfigMutator.AddClientProfile(
                        config,
                        Required(options, "id"),
                        ParsePermission(Optional(options, "permission") ?? "limited"),
                        SplitCsv(Optional(options, "tools") ?? "ssh_run,ssh_register,ssh_open_session,session_list,session_close,db_query,db_register,browser_login,browser_register,route_test,policy_check,credential_status,forget_credential,config_summary,audit_tail"));
                    break;

                case "set-default-profile":
                    ConfigMutator.SetDefaultProfile(config, Required(options, "id"));
                    break;

                case "set-session-timeout":
                    ConfigMutator.SetSessionIdleTimeout(config, OptionalInt(options, "minutes", 30));
                    break;

                case "add-credential":
                    ConfigMutator.AddCredential(
                        config,
                        Required(options, "alias"),
                        Required(options, "user"),
                        Optional(options, "label") ?? Required(options, "alias"));
                    break;

                case "add-ssh-target":
                    ConfigMutator.AddSshTarget(
                        config,
                        Required(options, "id"),
                        Required(options, "host"),
                        OptionalInt(options, "port", 22),
                        Required(options, "user"),
                        ParseSshAuthMode(Optional(options, "auth") ?? "password"),
                        Optional(options, "credential") ?? "",
                        Optional(options, "key-path"));
                    break;

                case "add-route":
                    ConfigMutator.AddRoute(
                        config,
                        Required(options, "id"),
                        Required(options, "chain").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
                    break;

                case "add-db-target":
                    ConfigMutator.AddDbTarget(
                        config,
                        Required(options, "id"),
                        ParseDbEngine(Required(options, "engine")),
                        Required(options, "host"),
                        OptionalInt(options, "port", DefaultDbPort(Required(options, "engine"))),
                        Required(options, "database"),
                        Required(options, "user"),
                        Required(options, "credential"),
                        Optional(options, "route"),
                        OptionalInt(options, "max-rows", 100));
                    break;

                case "add-browser-target":
                    ConfigMutator.AddBrowserTarget(
                        config,
                        Required(options, "id"),
                        Required(options, "url"),
                        Required(options, "user"),
                        Required(options, "credential"),
                        ParseBrowserIsolationMode(Optional(options, "isolation") ?? "managed-profile"),
                        Optional(options, "user-selector") ?? "",
                        Optional(options, "password-selector") ?? "",
                        Optional(options, "submit-selector") ?? "",
                        Optional(options, "success-selector"),
                        Optional(options, "success-url-contains"),
                        Optional(options, "failure-selector"),
                        OptionalInt(options, "timeout-seconds", 30));
                    break;

                case "add-ssh-policy":
                    ConfigMutator.AddSshPolicy(
                        config,
                        Required(options, "id"),
                        SplitCsv(Required(options, "routes")),
                        SplitCsv(Required(options, "prefixes")),
                        OptionalBool(options, "allow-shell-operators", false),
                        ParsePermission(Optional(options, "min-permission") ?? "limited"));
                    break;

                case "add-db-policy":
                    ConfigMutator.AddDbPolicy(
                        config,
                        Required(options, "id"),
                        SplitCsv(Required(options, "connections")),
                        OptionalBool(options, "allow-write-sql", false),
                        ParsePermission(Optional(options, "min-permission") ?? "limited"));
                    break;

                case "add-browser-policy":
                    ConfigMutator.AddBrowserPolicy(
                        config,
                        Required(options, "id"),
                        SplitCsv(Required(options, "targets")),
                        ParsePermission(Optional(options, "min-permission") ?? "limited"));
                    break;
            }

            var errors = AppConfigValidator.Validate(config);
            if (errors.Count > 0)
            {
                WriteJson(new { ok = false, code = "invalid_config", errors = ConfigErrorSanitizer.Sanitize(errors) });
                return 2;
            }

            AppConfigStore.Save(configPath, config);
            WriteJson(new { ok = true, config_path = configPath });
            return 0;
        }
        catch (Exception ex)
        {
            var safeError = SafeErrorFactory.FromException(ex);
            WriteJson(new { ok = false, code = safeError.Code, safe_message = safeError.Message });
            return 2;
        }
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Unexpected argument: {args[i]}");
            }

            var key = args[i][2..];
            if (string.IsNullOrWhiteSpace(key) || i + 1 >= args.Length)
            {
                throw new InvalidOperationException($"Missing value for option: {args[i]}");
            }

            options[key] = args[++i];
        }

        return options;
    }

    private static string Required(Dictionary<string, string> options, string key)
    {
        if (options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        throw new InvalidOperationException($"Missing required option --{key}.");
    }

    private static string? Optional(Dictionary<string, string> options, string key)
    {
        return options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
    }

    private static int OptionalInt(Dictionary<string, string> options, string key, int defaultValue)
    {
        if (!options.TryGetValue(key, out var value))
        {
            return defaultValue;
        }

        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException($"Option --{key} must be an integer.");
    }

    private static bool OptionalBool(Dictionary<string, string> options, string key, bool defaultValue)
    {
        if (!options.TryGetValue(key, out var value))
        {
            return defaultValue;
        }

        if (bool.TryParse(value, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException($"Option --{key} must be true or false.");
    }

    private static string[] SplitCsv(string value)
    {
        return value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    }

    private static SshAuthMode ParseSshAuthMode(string value)
    {
        return value.Equals("private-key", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("privatekey", StringComparison.OrdinalIgnoreCase)
            ? SshAuthMode.PrivateKey
            : value.Equals("password", StringComparison.OrdinalIgnoreCase)
                ? SshAuthMode.Password
                : throw new InvalidOperationException("--auth must be password or private-key.");
    }

    private static DbEngine ParseDbEngine(string value)
    {
        return value.Equals("postgres", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("postgresql", StringComparison.OrdinalIgnoreCase)
            ? DbEngine.Postgres
            : value.Equals("mysql", StringComparison.OrdinalIgnoreCase) ||
              value.Equals("mariadb", StringComparison.OrdinalIgnoreCase)
                ? DbEngine.MySql
                : throw new InvalidOperationException("--engine must be postgres or mysql.");
    }

    private static BrowserIsolationMode ParseBrowserIsolationMode(string value)
    {
        return value.Equals("managed-profile", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("managedprofile", StringComparison.OrdinalIgnoreCase)
            ? BrowserIsolationMode.ManagedProfile
            : value.Equals("extension-native-messaging", StringComparison.OrdinalIgnoreCase) ||
              value.Equals("extensionnativemessaging", StringComparison.OrdinalIgnoreCase)
                ? BrowserIsolationMode.ExtensionNativeMessaging
                : value.Equals("disabled", StringComparison.OrdinalIgnoreCase)
                    ? BrowserIsolationMode.Disabled
                    : throw new InvalidOperationException("--isolation must be managed-profile, extension-native-messaging, or disabled.");
    }

    private static PermissionProfile ParsePermission(string value)
    {
        return value.Equals("full", StringComparison.OrdinalIgnoreCase)
            ? PermissionProfile.Full
            : value.Equals("limited", StringComparison.OrdinalIgnoreCase)
                ? PermissionProfile.Limited
                : value.Equals("approval", StringComparison.OrdinalIgnoreCase)
                    ? PermissionProfile.Approval
                    : value.Equals("deny-by-default", StringComparison.OrdinalIgnoreCase) ||
                      value.Equals("denybydefault", StringComparison.OrdinalIgnoreCase)
                        ? PermissionProfile.DenyByDefault
                        : throw new InvalidOperationException("--min-permission must be full, limited, approval, or deny-by-default.");
    }

    private static int DefaultDbPort(string engine)
    {
        return ParseDbEngine(engine) == DbEngine.Postgres ? 5432 : 3306;
    }

    private static (string Profile, string[] Args) ParseProfile(string[] args, string defaultProfile)
    {
        var profile = defaultProfile;
        var rest = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--profile", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                profile = args[++i];
                continue;
            }

            rest.Add(args[i]);
        }

        return (profile, rest.ToArray());
    }

    private static async Task<int> RunCliToolAsync(Func<Task<int>> action)
    {
        try
        {
            return await action();
        }
        catch (CredentialUnavailableException ex)
        {
            WriteJson(new
            {
                ok = false,
                code = "credential_unavailable",
                credential_alias = ex.Alias
            });
            return 4;
        }
        catch (Exception ex)
        {
            var safeError = SafeErrorFactory.FromException(ex);
            WriteJson(new
            {
                ok = false,
                code = safeError.Code,
                safe_message = safeError.Message
            });
            return 5;
        }
    }

    private static (string[] SqlParts, IReadOnlyDictionary<string, object?> Parameters) ParseDbArgs(string[] args)
    {
        var sqlParts = new List<string>();
        var parameters = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--param", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                AddParameter(parameters, args[++i]);
                continue;
            }

            sqlParts.Add(args[i]);
        }

        return (sqlParts.ToArray(), parameters);
    }

    private static void AddParameter(Dictionary<string, object?> parameters, string assignment)
    {
        var separator = assignment.IndexOf('=');
        if (separator <= 0)
        {
            throw new InvalidOperationException("--param expects name=value.");
        }

        var name = assignment[..separator].Trim();
        var rawValue = assignment[(separator + 1)..];
        parameters[name] = ParseScalar(rawValue);
    }

    private static object? ParseScalar(string rawValue)
    {
        if (rawValue.Equals("null", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (bool.TryParse(rawValue, out var boolean))
        {
            return boolean;
        }

        if (long.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var integer))
        {
            return integer;
        }

        if (decimal.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var number))
        {
            return number;
        }

        return rawValue;
    }

    private static PolicyDecision EvaluatePolicyCheck(
        PolicyEvaluator policy,
        AppConfig config,
        string requestedTool,
        string profile,
        string? routeId,
        string? connectionId,
        string? targetId,
        string command,
        string sql)
    {
        if (!IsKnownTool(requestedTool))
        {
            return PolicyDecision.Deny("unknown tool");
        }

        if (!IsToolAllowedForProfile(config, requestedTool, profile))
        {
            return PolicyDecision.Deny("tool is not allowed for this client profile");
        }

        if (requestedTool == "ssh_open_session")
        {
            return policy.Evaluate(new ToolRequest("route_test", profile, RouteId: routeId));
        }

        if (requestedTool is "ssh_run" or "route_test" or "db_query" or "browser_login")
        {
            return policy.Evaluate(new ToolRequest(
                requestedTool,
                profile,
                RouteId: routeId,
                ConnectionId: connectionId,
                BrowserTargetId: targetId,
                Command: command,
                Sql: sql));
        }

        return PolicyDecision.Allow();
    }

    private static bool EnsureAllowed(
        IApprovalPrompt approvalPrompt,
        ApprovalCache approvalCache,
        PolicyDecision decision,
        string clientProfile,
        string title,
        string target,
        string action)
    {
        if (decision.Allowed)
        {
            return true;
        }

        if (!decision.NeedsApproval)
        {
            return false;
        }

        var safeAction = SafeAction(action);
        var reason = decision.Reason ?? "Policy requires approval.";
        if (approvalCache.IsApproved(clientProfile, title, target, safeAction, reason))
        {
            return true;
        }

        var approved = approvalPrompt.Approve(title, target, safeAction, reason);
        if (approved)
        {
            approvalCache.Remember(clientProfile, title, target, safeAction, reason);
        }

        return approved;
    }

    private static bool IsToolAllowedForProfile(AppConfig config, string toolName, string clientProfile)
    {
        var profile = config.ClientProfiles.FirstOrDefault(profile =>
            profile.Id.Equals(clientProfile, StringComparison.OrdinalIgnoreCase));

        return profile is not null &&
            (profile.AllowedTools.Count == 0 ||
             profile.AllowedTools.Contains(toolName, StringComparer.OrdinalIgnoreCase));
    }

    private static bool IsConfiguredClientProfile(AppConfig config, string clientProfile) =>
        config.ClientProfiles.Any(profile => profile.Id.Equals(clientProfile, StringComparison.OrdinalIgnoreCase));

    private static int DenyUnknownClientProfile(AuditLogger audit, string toolName, string action)
    {
        audit.Record(toolName, "unknown", "profile", action, "denied", "client profile is not configured");
        WriteJson(new
        {
            ok = false,
            code = "unknown_client_profile",
            reason = "client profile is not configured",
            needsApproval = false,
            secret_visible_to_model = false
        });
        return 3;
    }

    private static string ResolveMcpClientProfile(AppConfig config)
    {
        var lockedProfile = Environment.GetEnvironmentVariable(McpClientConfigFactory.ClientProfileEnvironmentVariable);
        var profile = string.IsNullOrWhiteSpace(lockedProfile) ? config.DefaultClientProfile : lockedProfile;
        if (!IsConfiguredClientProfile(config, profile))
        {
            throw new InvalidOperationException("Configured MCP client profile does not exist.");
        }

        return profile;
    }

    private static string NormalizeToolName(string toolName) => toolName.Trim().ToLowerInvariant();

    private static bool IsKnownTool(string toolName)
    {
        return toolName is "ssh_run" or "ssh_register" or "ssh_open_session" or "session_list" or "session_close" or
            "browser_login" or "browser_register" or "db_query" or "db_register" or "route_test" or "policy_check" or
            "credential_status" or "forget_credential" or "config_summary" or "audit_tail";
    }

    private static bool IsConfiguredCredentialAlias(AppConfig config, string alias) =>
        config.Credentials.Any(credential => credential.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase));

    private static string SafeAction(string action)
    {
        action = action.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return action.Length <= 500 ? action : action[..500] + "...";
    }

    private static void WriteJson(object value)
    {
        Console.WriteLine(JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }
}

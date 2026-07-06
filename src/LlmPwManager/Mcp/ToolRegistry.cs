using System.Text.Json;
using LlmPwManager.Audit;
using LlmPwManager.Browser;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Db;
using LlmPwManager.Policy;
using LlmPwManager.Security;
using LlmPwManager.Ssh;
using LlmPwManager.Ui;

namespace LlmPwManager.Mcp;

internal sealed class ToolRegistry(
    AppConfig config,
    PolicyEvaluator policy,
    IApprovalPrompt approval,
    ApprovalCache approvalCache,
    AuditLogger audit,
    AuditLogReader auditReader,
    CredentialResolver credentials,
    SshExecutor ssh,
    SshSessionManager sshSessions,
    DbExecutor db,
    IBrowserLoginExecutor browser,
    ConfigSummary summary,
    string mcpClientProfile,
    ISshRegistrationService? sshRegistration = null,
    IDbRegistrationService? dbRegistration = null,
    IBrowserRegistrationService? browserRegistration = null)
{
    public IReadOnlyList<object> ListTools()
    {
        object[] tools =
        [
        new
        {
            name = "ssh_run",
            description = "Use this instead of raw ssh when the user asks to run a command on a configured SSH route or reusable SSH session. The broker resolves SSH passwords or key passphrases locally, enforces policy, redacts secrets from stdout/stderr, and never exposes credentials to the model.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    route_id = StringProperty("Configured SSH route id to use when no session_id is supplied. Get available route ids from config_summary."),
                    session_id = StringProperty("Opaque SSH session id previously returned by ssh_open_session. Use this for multi-step work over the same route."),
                    command = StringProperty("Shell command to run on the final SSH hop. The command is still checked against broker policy before execution."),
                    purpose = PurposeProperty("Why this SSH command is needed for the user's request."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "command", "purpose" }
            }
        },
        new
        {
            name = "ssh_register",
            description = "Use this when an SSH host or route is not registered yet. It asks the local user to approve registration, creates non-secret config for a direct or SSH-routed target, prompts locally for the SSH password, tests it, and never exposes the password to the model.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    route_id = StringProperty("New route id and SSH target id to register. Use a short stable id such as prod-bastion."),
                    target_id = StringProperty("Optional SSH target id to create. Defaults to route_id. Use this when route_id describes a chain such as bastion-to-app but the final target should be app."),
                    via_route_id = StringProperty("Optional existing SSH route id to reach this new SSH host. Use this for SSH->SSH paths, such as registering an inner host through an already registered bastion route."),
                    host = StringProperty("SSH host name or IP address to register. Do not include a password or URI userinfo."),
                    port = PortProperty("SSH TCP port. Defaults to 22 when omitted."),
                    user_name = StringProperty("SSH login user name for the target."),
                    purpose = PurposeProperty("Why this new SSH target should be registered."),
                    command_prefixes = new
                    {
                        type = "array",
                        description = "Optional safe command prefixes to allow for this route, such as whoami, hostname, uptime, or systemctl status.",
                        items = new { type = "string" }
                    },
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "route_id", "host", "user_name", "purpose" }
            }
        },
        new
        {
            name = "ssh_open_session",
            description = "Use this for multi-step SSH or DB work over the same configured route. It opens a broker-held SSH connection and returns an opaque session_id; credentials remain isolated inside the broker process.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    route_id = StringProperty("Configured SSH route id to keep open. Get available route ids from config_summary."),
                    purpose = PurposeProperty("Why a reusable SSH session is needed for the user's request."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "route_id", "purpose" }
            }
        },
        new
        {
            name = "session_list",
            description = "Use this to inspect active broker-managed SSH sessions for the current client profile. It returns session metadata only and never exposes credentials.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    client_profile = ClientProfileProperty()
                }
            }
        },
        new
        {
            name = "session_close",
            description = "Use this to close an active broker-managed SSH session when multi-step work is finished or the user asks to stop using it.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    session_id = StringProperty("Opaque session id returned by ssh_open_session."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "session_id" }
            }
        },
        new
        {
            name = "browser_login",
            description = "Use this instead of asking for a browser password when the user wants to log in to a configured browser target. The broker opens an isolated Edge profile, fills only configured selectors, verifies login locally, and never exposes the password, cookies, or page secrets to the model.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    target_id = StringProperty("Configured browser login target id. Get available browser target ids from config_summary."),
                    purpose = PurposeProperty("Why this browser login is needed for the user's request."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "target_id", "purpose" }
            }
        },
        new
        {
            name = "browser_register",
            description = "Use this when a browser login target is not registered yet. It asks the local user to approve registration, stores non-secret selector config, prompts locally for the password, verifies login, and never exposes the password to the model.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    target_id = StringProperty("New browser login target id to register."),
                    login_url = StringProperty("Login page URL to open in the broker-managed isolated Edge profile."),
                    user_name = StringProperty("Login user name or email to fill into the configured user selector."),
                    user_name_selector = StringProperty("CSS selector for the username input. Do not include secret values."),
                    password_selector = StringProperty("CSS selector for the password input. The password value is provided only by the local prompt."),
                    submit_selector = StringProperty("CSS selector for the login submit button."),
                    success_selector = StringProperty("Optional CSS selector that indicates login success."),
                    success_url_contains = StringProperty("Optional URL substring that indicates login success."),
                    failure_selector = StringProperty("Optional CSS selector that indicates login failure."),
                    login_timeout_seconds = PositiveIntegerProperty("Seconds to wait for login fields and success/failure checks. Minimum is 5.", minimum: 5),
                    purpose = PurposeProperty("Why this browser target should be registered."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "target_id", "login_url", "user_name", "user_name_selector", "password_selector", "submit_selector", "purpose" }
            }
        },
        new
        {
            name = "db_query",
            description = "Use this instead of raw psql/mysql when the user asks to query a configured database, including databases behind SSH routes or reusable SSH sessions. The broker resolves DB and SSH credentials locally, enforces SQL policy, redacts secret-like result values, and never exposes passwords or connection strings to the model.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    connection_id = StringProperty("Configured DB connection id. Get available DB target ids from config_summary."),
                    session_id = StringProperty("Optional opaque SSH session id from ssh_open_session when reusing an already-open route."),
                    sql = StringProperty("SQL query to run. The broker checks whether write SQL is allowed by policy before execution."),
                    @params = ObjectProperty("Optional SQL parameters keyed by parameter name, without passwords or connection strings."),
                    purpose = PurposeProperty("Why this DB query is needed for the user's request."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "connection_id", "sql", "purpose" }
            }
        },
        new
        {
            name = "db_register",
            description = "Use this when a DB connection is not registered yet. It asks the local user to approve registration, stores non-secret DB metadata, prompts locally for the DB password, tests the connection, and never exposes the password or connection string to the model.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    connection_id = StringProperty("New DB connection id to register."),
                    engine = new { type = "string", description = "Database engine for this connection.", @enum = new[] { "postgres", "mysql" } },
                    host = StringProperty("DB host name or IP as seen from the selected route. For DB on the inner SSH host, this is often 127.0.0.1."),
                    port = PortProperty("DB TCP port. Defaults to the engine port when omitted."),
                    database = StringProperty("Database/schema name."),
                    user_name = StringProperty("DB login user name."),
                    route_id = StringProperty("Optional configured SSH route id to reach this DB. Use for SSH->DB or SSH->SSH->DB paths."),
                    max_rows = PositiveIntegerProperty("Maximum rows to return before truncation.", minimum: 1),
                    allow_write_sql = BooleanProperty("Whether policy should allow write SQL for this DB target. Prefer false for read-only tasks."),
                    purpose = PurposeProperty("Why this DB connection should be registered."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "connection_id", "engine", "host", "database", "user_name", "purpose" }
            }
        },
        new
        {
            name = "route_test",
            description = "Use this before ssh_run or db_query when SSH connectivity is uncertain. It tests a configured SSH route, including nested hops, without returning credentials.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    route_id = StringProperty("Configured SSH route id to test. Get available route ids from config_summary."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "route_id" }
            }
        },
        new
        {
            name = "policy_check",
            description = "Use this to decide whether a proposed SSH command, DB query, route, or browser action would be allowed before executing it. It never opens credential prompts, never performs the action, and never exposes secrets.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    tool_name = StringProperty("Tool name to check, such as ssh_run, db_query, route_test, or browser_login."),
                    route_id = StringProperty("Optional SSH route id for SSH-related policy checks."),
                    connection_id = StringProperty("Optional DB connection id for DB policy checks."),
                    target_id = StringProperty("Optional browser target id for browser policy checks."),
                    command = StringProperty("Optional SSH command to check against command-prefix policy."),
                    sql = StringProperty("Optional SQL text to check against read/write policy."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "tool_name" }
            }
        },
        new
        {
            name = "credential_status",
            description = "Use this before asking the user about credentials. It reports whether a configured credential alias is present in the local credential store. Unknown aliases are not queried, and the secret value is never returned.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    alias = StringProperty("Configured credential alias to check. Get aliases or counts from config_summary when allowed by the profile."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "alias" }
            }
        },
        new
        {
            name = "forget_credential",
            description = "Use this only when the user asks to clear a stored credential or force the next operation to prompt locally again. It deletes a configured credential alias from the local credential store; unknown aliases are not deleted and secrets are never returned.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    alias = StringProperty("Configured credential alias to delete from the local credential store."),
                    client_profile = ClientProfileProperty()
                },
                required = new[] { "alias" }
            }
        },
        new
        {
            name = "config_summary",
            description = "Use this first when the user asks what SSH routes, DB targets, browser targets, credential aliases, or broker permissions are configured. It returns a profile-scoped, secret-free summary and helps choose route_id, connection_id, target_id, and credential aliases for later tool calls.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    client_profile = ClientProfileProperty()
                }
            }
        },
        new
        {
            name = "audit_tail",
            description = "Use this when the user asks what broker actions recently happened. It returns recent secret-free audit log entries for allowed client profiles.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    limit = RangedIntegerProperty("Maximum number of recent audit entries to return.", minimum: 1, maximum: 500),
                    client_profile = ClientProfileProperty()
                }
            }
        }
        ];

        return tools
            .Where(tool => IsToolAllowedForProfile(ToolName(tool), mcpClientProfile))
            .ToList();
    }

    private static object StringProperty(string description) => new
    {
        type = "string",
        description
    };

    private static object PurposeProperty(string description) => StringProperty(description);

    private static object ClientProfileProperty() => StringProperty(
        "Optional broker client profile. MCP servers are locked to LLM_PW_MANAGER_CLIENT_PROFILE, so omit this unless the client passes the same locked profile for compatibility.");

    private static object PortProperty(string description) => new
    {
        type = "integer",
        description,
        minimum = 1,
        maximum = 65535
    };

    private static object PositiveIntegerProperty(string description, int minimum) => new
    {
        type = "integer",
        description,
        minimum
    };

    private static object RangedIntegerProperty(string description, int minimum, int maximum) => new
    {
        type = "integer",
        description,
        minimum,
        maximum
    };

    private static object BooleanProperty(string description) => new
    {
        type = "boolean",
        description
    };

    private static object ObjectProperty(string description) => new
    {
        type = "object",
        description,
        additionalProperties = true
    };

    public async Task<object> CallAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        if (!TryReadToolCall(parameters, out var name, out var args))
        {
            return ToolError("invalid_request", new { safe_message = "Tool call parameters were invalid." });
        }

        try
        {
            return name switch
            {
                "ssh_run" => await SshRunAsync(args, cancellationToken),
                "ssh_register" => await SshRegisterAsync(args, cancellationToken),
                "ssh_open_session" => await SshOpenSessionAsync(args, cancellationToken),
                "session_list" => SessionList(args),
                "session_close" => SessionClose(args),
                "browser_login" => await BrowserLoginAsync(args, cancellationToken),
                "browser_register" => await BrowserRegisterAsync(args, cancellationToken),
                "db_query" => await DbQueryAsync(args, cancellationToken),
                "db_register" => await DbRegisterAsync(args, cancellationToken),
                "route_test" => await RouteTestAsync(args, cancellationToken),
                "policy_check" => PolicyCheck(args),
                "credential_status" => CredentialStatus(args),
                "forget_credential" => ForgetCredential(args),
                "config_summary" => ConfigSummary(args),
                "audit_tail" => AuditTail(args),
                _ => ToolError("unknown_tool")
            };
        }
        catch (CredentialUnavailableException ex)
        {
            return ToolError("credential_unavailable", new { credential_alias = ex.Alias });
        }
        catch (ClientProfileLockException ex)
        {
            return ToolError("client_profile_locked", new
            {
                reason = ex.Message,
                client_profile = ex.EffectiveProfile,
                needsApproval = false
            });
        }
        catch (Exception ex)
        {
            var safeError = SafeErrorFactory.FromException(ex);
            return ToolError(safeError.Code, new { safe_message = safeError.Message });
        }
    }

    private static bool TryReadToolCall(JsonElement parameters, out string name, out JsonElement args)
    {
        name = "";
        args = default;

        if (parameters.ValueKind != JsonValueKind.Object ||
            !parameters.TryGetProperty("name", out var nameElement) ||
            nameElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        name = nameElement.GetString() ?? "";
        if (!parameters.TryGetProperty("arguments", out args) ||
            args.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            args = default;
            return true;
        }

        return args.ValueKind == JsonValueKind.Object;
    }

    private async Task<object> SshRegisterAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var routeId = ReadString(args, "route_id");
        var targetId = ReadOptionalString(args, "target_id") ?? routeId;
        var viaRouteId = ReadOptionalString(args, "via_route_id");
        var host = ReadString(args, "host");
        var port = ReadInt(args, "port", 22);
        var userName = ReadString(args, "user_name");
        var purpose = ReadString(args, "purpose");
        var clientProfile = ReadClientProfile(args);
        var commandPrefixes = ReadStringList(args, "command_prefixes", ["uptime", "whoami", "hostname"]);

        if (!IsToolAllowedForProfile("ssh_register", clientProfile))
        {
            audit.Record("ssh_register", clientProfile, "ssh", "register SSH target", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (sshRegistration is null)
        {
            audit.Record("ssh_register", clientProfile, "ssh", "register SSH target", "denied", "SSH registration is not available");
            return ToolError("unsupported_operation", new { safe_message = "SSH registration is not available in this process." });
        }

        if (string.IsNullOrWhiteSpace(routeId) ||
            string.IsNullOrWhiteSpace(host) ||
            string.IsNullOrWhiteSpace(userName) ||
            !ConfigIdentifier.IsValid(routeId) ||
            string.IsNullOrWhiteSpace(targetId) ||
            !ConfigIdentifier.IsValid(targetId))
        {
            return ToolError("invalid_request", new { safe_message = "SSH registration requires a valid route_id, target_id, host, and user_name." });
        }

        if (port is < 1 or > 65535)
        {
            return ToolError("invalid_request", new { safe_message = "SSH port must be between 1 and 65535." });
        }

        if (!string.IsNullOrWhiteSpace(viaRouteId) && !IsConfiguredRoute(viaRouteId))
        {
            return ToolError("ssh_route_not_registered", new
            {
                safe_message = "The requested parent SSH route is not registered. Register that route first with ssh_register, then retry nested ssh_register.",
                suggested_tool = "ssh_register",
                needs_user_registration = true,
                secret_visible_to_model = false
            });
        }

        if (!string.IsNullOrWhiteSpace(viaRouteId) &&
            viaRouteId.Equals(routeId, StringComparison.OrdinalIgnoreCase))
        {
            return ToolError("invalid_request", new { safe_message = "SSH registration cannot use the new route_id as its own via_route_id." });
        }

        var target = string.IsNullOrWhiteSpace(viaRouteId)
            ? $"{userName}@{host}:{port}"
            : $"{viaRouteId} -> {userName}@{host}:{port}";
        var approved = approval.Approve(
            "SSH target registration required",
            target,
            SafeAction(purpose),
            "This SSH address is not registered. Approve only if you recognize it. The password prompt will stay local and the model will not see the password.");
        if (!approved)
        {
            audit.Record("ssh_register", clientProfile, "ssh", "register SSH target", "denied", "user denied SSH target registration");
            return ToolError("user_denied", new { safe_message = "The local user denied SSH target registration." });
        }

        var result = await sshRegistration.RegisterPasswordAsync(
            new SshRegistrationRequest(routeId, targetId, host, port, userName, viaRouteId, purpose, commandPrefixes, clientProfile),
            cancellationToken);

        audit.Record("ssh_register", clientProfile, result.RouteId, "register SSH target", result.Status);
        return ToolText(new
        {
            status = result.Status,
            route_id = result.RouteId,
            target_id = result.TargetId,
            via_route_id = viaRouteId,
            credential_alias = result.CredentialAlias,
            prompt_shown = result.PromptShown,
            secret_visible_to_model = false
        });
    }

    private async Task<object> SshRunAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var routeId = ReadOptionalString(args, "route_id");
        var sessionId = ReadOptionalString(args, "session_id");
        var command = ReadString(args, "command");
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("ssh_run", clientProfile))
        {
            audit.Record("ssh_run", clientProfile, "ssh", SafeAction(command), "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            if (!sshSessions.TryGetInfo(sessionId, clientProfile, out var sessionInfo))
            {
                audit.Record("ssh_run", clientProfile, "session", SafeAction(command), "denied", "SSH session was not found");
                return ToolError("session_not_found");
            }

            routeId = sessionInfo.RouteId;
        }

        if (string.IsNullOrWhiteSpace(routeId))
        {
            throw new InvalidOperationException("Missing required argument: route_id or session_id");
        }

        if (!IsConfiguredRoute(routeId))
        {
            audit.Record("ssh_run", clientProfile, "ssh", SafeAction(command), "denied", "SSH route is not registered");
            return ToolError("ssh_route_not_registered", new
            {
                safe_message = "The requested SSH route is not registered. Ask the local user to approve ssh_register for this host before running SSH commands.",
                suggested_tool = "ssh_register",
                needs_user_registration = true,
                secret_visible_to_model = false
            });
        }

        var decision = policy.Evaluate(new ToolRequest("ssh_run", clientProfile, RouteId: routeId, Command: command));
        if (!EnsureAllowed(decision, clientProfile, "SSH command approval required", routeId, command))
        {
            audit.Record("ssh_run", clientProfile, routeId, SafeAction(command), "denied", decision.Reason);
            return ToolError("policy_denied", new { decision.Reason, decision.NeedsApproval });
        }

        var result = string.IsNullOrWhiteSpace(sessionId)
            ? await ssh.RunCommandAsync(routeId, command, cancellationToken)
            : await sshSessions.RunCommandAsync(sessionId, clientProfile, command, cancellationToken);
        audit.Record("ssh_run", clientProfile, routeId, SafeAction(command), "ok");
        return ToolText(new
        {
            route_id = routeId,
            session_id = sessionId,
            exit_status = result.ExitStatus,
            stdout = result.Stdout,
            stderr = result.Stderr,
            secret_visible_to_model = false
        });
    }

    private async Task<object> SshOpenSessionAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var routeId = ReadString(args, "route_id");
        var purpose = ReadString(args, "purpose");
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("ssh_open_session", clientProfile))
        {
            audit.Record("ssh_open_session", clientProfile, "ssh", SafeAction(purpose), "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (!IsConfiguredRoute(routeId))
        {
            audit.Record("ssh_open_session", clientProfile, "ssh", SafeAction(purpose), "denied", "SSH route is not registered");
            return ToolError("ssh_route_not_registered", new
            {
                safe_message = "The requested SSH route is not registered. Ask the local user to approve ssh_register for this host before opening an SSH session.",
                suggested_tool = "ssh_register",
                needs_user_registration = true,
                secret_visible_to_model = false
            });
        }

        var decision = policy.Evaluate(new ToolRequest("route_test", clientProfile, RouteId: routeId));
        if (!EnsureAllowed(decision, clientProfile, "SSH session approval required", routeId, purpose))
        {
            audit.Record("ssh_open_session", clientProfile, routeId, SafeAction(purpose), "denied", decision.Reason);
            return ToolError("policy_denied", new { decision.Reason, decision.NeedsApproval });
        }

        var session = await sshSessions.OpenAsync(routeId, clientProfile, purpose, cancellationToken);
        audit.Record("ssh_open_session", clientProfile, routeId, SafeAction(purpose), "ok");
        return ToolText(new
        {
            session_id = session.SessionId,
            route_id = session.RouteId,
            client_profile = session.ClientProfile,
            purpose = session.Purpose,
            created_at = session.CreatedAt,
            last_used_at = session.LastUsedAt,
            expires_at = session.ExpiresAt,
            secret_visible_to_model = false
        });
    }

    private async Task<object> DbQueryAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var connectionId = ReadString(args, "connection_id");
        var sessionId = ReadOptionalString(args, "session_id");
        var sql = ReadString(args, "sql");
        var parameters = ReadParameters(args);
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("db_query", clientProfile))
        {
            audit.Record("db_query", clientProfile, "db", SafeAction(sql), "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (!IsConfiguredDbTarget(connectionId))
        {
            audit.Record("db_query", clientProfile, "db", SafeAction(sql), "denied", "DB connection is not registered");
            return ToolError("db_connection_not_registered", new
            {
                safe_message = "The requested DB connection is not registered. Ask the local user to approve db_register for this database before running queries.",
                suggested_tool = "db_register",
                needs_user_registration = true,
                secret_visible_to_model = false
            });
        }

        var decision = policy.Evaluate(new ToolRequest("db_query", clientProfile, ConnectionId: connectionId, Sql: sql));
        if (!EnsureAllowed(decision, clientProfile, "DB query approval required", connectionId, sql))
        {
            audit.Record("db_query", clientProfile, connectionId, SafeAction(sql), "denied", decision.Reason);
            return ToolError("policy_denied", new { decision.Reason, decision.NeedsApproval });
        }

        SshSessionInfo? sessionInfo = null;
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            if (!sshSessions.TryGetInfo(sessionId, clientProfile, out var foundSession))
            {
                audit.Record("db_query", clientProfile, connectionId, "query through missing SSH session", "denied", "SSH session was not found");
                return ToolError("session_not_found");
            }

            sessionInfo = foundSession;
            var target = config.DbTargets.Single(dbTarget =>
                dbTarget.Id.Equals(connectionId, StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrWhiteSpace(target.RouteId))
            {
                audit.Record("db_query", clientProfile, connectionId, SafeAction(sql), "denied", "DB connection is not configured for SSH routing");
                return ToolError("session_not_applicable", new { connection_id = connectionId });
            }

            if (!target.RouteId.Equals(sessionInfo.RouteId, StringComparison.OrdinalIgnoreCase))
            {
                audit.Record("db_query", clientProfile, connectionId, SafeAction(sql), "denied", "SSH session route does not match DB connection route");
                return ToolError("session_route_mismatch", new
                {
                    connection_id = connectionId,
                    connection_route_id = target.RouteId,
                    session_route_id = sessionInfo.RouteId
                });
            }
        }

        var result = sessionInfo is null
            ? await db.QueryAsync(connectionId, sql, parameters, cancellationToken)
            : await sshSessions.UseConnectionAsync(
                sessionInfo.SessionId,
                clientProfile,
                (route, token) => db.QueryAsync(connectionId, sql, parameters, route, token),
                cancellationToken);
        audit.Record("db_query", clientProfile, connectionId, SafeAction(sql), "ok");
        return ToolText(new
        {
            connection_id = connectionId,
            session_id = sessionInfo?.SessionId,
            columns = result.Columns,
            rows = result.Rows,
            truncated = result.Truncated,
            redacted_columns = result.RedactedColumns,
            secret_visible_to_model = false
            });
    }

    private async Task<object> DbRegisterAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var connectionId = ReadString(args, "connection_id");
        var engine = ParseDbEngine(ReadString(args, "engine"));
        var host = ReadString(args, "host");
        var port = ReadInt(args, "port", DefaultDbPort(engine));
        var database = ReadString(args, "database");
        var userName = ReadString(args, "user_name");
        var routeId = ReadOptionalString(args, "route_id");
        var maxRows = ReadInt(args, "max_rows", 100);
        var allowWriteSql = ReadBool(args, "allow_write_sql", false);
        var purpose = ReadString(args, "purpose");
        var clientProfile = ReadClientProfile(args);

        if (!IsToolAllowedForProfile("db_register", clientProfile))
        {
            audit.Record("db_register", clientProfile, "db", "register DB target", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (dbRegistration is null)
        {
            audit.Record("db_register", clientProfile, "db", "register DB target", "denied", "DB registration is not available");
            return ToolError("unsupported_operation", new { safe_message = "DB registration is not available in this process." });
        }

        if (string.IsNullOrWhiteSpace(connectionId) ||
            string.IsNullOrWhiteSpace(host) ||
            string.IsNullOrWhiteSpace(database) ||
            string.IsNullOrWhiteSpace(userName) ||
            !ConfigIdentifier.IsValid(connectionId) ||
            port is < 1 or > 65535 ||
            maxRows < 1)
        {
            return ToolError("invalid_request", new { safe_message = "DB registration requires a valid connection_id, host, port, database, user_name, and max_rows." });
        }

        if (!string.IsNullOrWhiteSpace(routeId) && !IsConfiguredRoute(routeId))
        {
            return ToolError("ssh_route_not_registered", new
            {
                safe_message = "The requested DB SSH route is not registered. Register the SSH route first with ssh_register, then retry db_register.",
                suggested_tool = "ssh_register",
                needs_user_registration = true,
                secret_visible_to_model = false
            });
        }

        var approved = approval.Approve(
            "DB target registration required",
            $"{engine}://{userName}@{host}:{port}/{database}",
            SafeAction(purpose),
            "This DB connection is not registered. Approve only if you recognize it. The password prompt will stay local and the model will not see the password.");
        if (!approved)
        {
            audit.Record("db_register", clientProfile, "db", "register DB target", "denied", "user denied DB target registration");
            return ToolError("user_denied", new { safe_message = "The local user denied DB target registration." });
        }

        var result = await dbRegistration.RegisterAsync(
            new DbRegistrationRequest(connectionId, engine, host, port, database, userName, routeId, maxRows, allowWriteSql, purpose, clientProfile),
            cancellationToken);
        audit.Record("db_register", clientProfile, result.ConnectionId, "register DB target", result.Status);
        return ToolText(new
        {
            status = result.Status,
            connection_id = result.ConnectionId,
            credential_alias = result.CredentialAlias,
            prompt_shown = result.PromptShown,
            secret_visible_to_model = false
        });
    }

    private async Task<object> BrowserLoginAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var targetId = ReadString(args, "target_id");
        var purpose = ReadString(args, "purpose");
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("browser_login", clientProfile))
        {
            audit.Record("browser_login", clientProfile, "browser", SafeAction(purpose), "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        var target = config.BrowserTargets.FirstOrDefault(browserTarget =>
            browserTarget.Id.Equals(targetId, StringComparison.OrdinalIgnoreCase));
        if (target is null)
        {
            audit.Record("browser_login", clientProfile, "browser", SafeAction(purpose), "denied", "browser target is not registered");
            return ToolError("browser_target_not_registered", new
            {
                safe_message = "The requested browser login target is not registered. Ask the local user to approve browser_register before logging in.",
                suggested_tool = "browser_register",
                needs_user_registration = true,
                secret_visible_to_model = false
            });
        }

        var decision = policy.Evaluate(new ToolRequest("browser_login", clientProfile, BrowserTargetId: targetId));
        if (!EnsureAllowed(decision, clientProfile, "Browser login approval required", targetId, purpose))
        {
            audit.Record("browser_login", clientProfile, targetId, SafeAction(purpose), "denied", decision.Reason);
            return ToolError("policy_denied", new { decision.Reason, decision.NeedsApproval });
        }

        var result = await browser.LoginAsync(target, cancellationToken);
        audit.Record("browser_login", clientProfile, targetId, SafeAction(purpose), result.Success ? "ok" : result.Status, result.SafeMessage);
        return result.Success
            ? ToolText(new
            {
                target_id = targetId,
                status = result.Status,
                secret_visible_to_model = false
            })
            : ToolError(result.Status, new { safe_message = result.SafeMessage });
    }

    private async Task<object> BrowserRegisterAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var targetId = ReadString(args, "target_id");
        var loginUrl = ReadString(args, "login_url");
        var userName = ReadString(args, "user_name");
        var userNameSelector = ReadString(args, "user_name_selector");
        var passwordSelector = ReadString(args, "password_selector");
        var submitSelector = ReadString(args, "submit_selector");
        var successSelector = ReadOptionalString(args, "success_selector");
        var successUrlContains = ReadOptionalString(args, "success_url_contains");
        var failureSelector = ReadOptionalString(args, "failure_selector");
        var loginTimeoutSeconds = ReadInt(args, "login_timeout_seconds", 30);
        var purpose = ReadString(args, "purpose");
        var clientProfile = ReadClientProfile(args);

        if (!IsToolAllowedForProfile("browser_register", clientProfile))
        {
            audit.Record("browser_register", clientProfile, "browser", "register browser target", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (browserRegistration is null)
        {
            audit.Record("browser_register", clientProfile, "browser", "register browser target", "denied", "browser registration is not available");
            return ToolError("unsupported_operation", new { safe_message = "Browser registration is not available in this process." });
        }

        if (string.IsNullOrWhiteSpace(targetId) ||
            string.IsNullOrWhiteSpace(loginUrl) ||
            string.IsNullOrWhiteSpace(userName) ||
            string.IsNullOrWhiteSpace(userNameSelector) ||
            string.IsNullOrWhiteSpace(passwordSelector) ||
            string.IsNullOrWhiteSpace(submitSelector) ||
            (string.IsNullOrWhiteSpace(successSelector) && string.IsNullOrWhiteSpace(successUrlContains)) ||
            !ConfigIdentifier.IsValid(targetId) ||
            loginTimeoutSeconds < 5)
        {
            return ToolError("invalid_request", new { safe_message = "Browser registration requires a valid target_id, login_url, selectors, success condition, user_name, and timeout." });
        }

        var approved = approval.Approve(
            "Browser login registration required",
            loginUrl,
            SafeAction(purpose),
            "This browser login target is not registered. Approve only if you recognize it. The password prompt will stay local and the model will not see the password.");
        if (!approved)
        {
            audit.Record("browser_register", clientProfile, "browser", "register browser target", "denied", "user denied browser target registration");
            return ToolError("user_denied", new { safe_message = "The local user denied browser target registration." });
        }

        var result = await browserRegistration.RegisterAsync(
            new BrowserRegistrationRequest(
                targetId,
                loginUrl,
                userName,
                userNameSelector,
                passwordSelector,
                submitSelector,
                successSelector,
                successUrlContains,
                failureSelector,
                loginTimeoutSeconds,
                purpose,
                clientProfile),
            cancellationToken);
        audit.Record("browser_register", clientProfile, result.TargetId, "register browser target", result.Status, result.SafeMessage);
        return result.Success
            ? ToolText(new
            {
                status = result.Status,
                target_id = result.TargetId,
                credential_alias = result.CredentialAlias,
                prompt_shown = result.PromptShown,
                secret_visible_to_model = false
            })
            : ToolError(result.Status, new { safe_message = result.SafeMessage });
    }

    private async Task<object> RouteTestAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var routeId = ReadString(args, "route_id");
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("route_test", clientProfile))
        {
            audit.Record("route_test", clientProfile, "ssh", "test route connectivity", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (!IsConfiguredRoute(routeId))
        {
            audit.Record("route_test", clientProfile, "ssh", "test route connectivity", "denied", "SSH route is not registered");
            return ToolError("ssh_route_not_registered", new
            {
                safe_message = "The requested SSH route is not registered. Ask the local user to approve ssh_register for this host before testing connectivity.",
                suggested_tool = "ssh_register",
                needs_user_registration = true,
                secret_visible_to_model = false
            });
        }

        var decision = policy.Evaluate(new ToolRequest("route_test", clientProfile, RouteId: routeId));
        if (!EnsureAllowed(decision, clientProfile, "Route test approval required", routeId, "test route connectivity"))
        {
            audit.Record("route_test", clientProfile, routeId, "test route connectivity", "denied", decision.Reason);
            return ToolError("policy_denied", new { decision.Reason, decision.NeedsApproval });
        }

        using var route = await ssh.ConnectRouteAsync(routeId, cancellationToken);
        audit.Record("route_test", clientProfile, routeId, "test route connectivity", "ok");
        return ToolText(new { route_id = routeId, status = "ok" });
    }

    private object CredentialStatus(JsonElement args)
    {
        var alias = ReadString(args, "alias");
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("credential_status", clientProfile))
        {
            audit.Record("credential_status", clientProfile, alias, "read credential status", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (!IsConfiguredCredentialAlias(alias))
        {
            audit.Record("credential_status", clientProfile, "credential", "read unknown credential status", "unknown", "credential alias is not configured");
            return ToolText(new
            {
                status = "unknown",
                configured = false,
                secret_visible_to_model = false
            });
        }

        return ToolText(new
        {
            alias,
            status = credentials.Exists(alias) ? "registered" : "missing",
            configured = true,
            secret_visible_to_model = false
        });
    }

    private object PolicyCheck(JsonElement args)
    {
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("policy_check", clientProfile))
        {
            audit.Record("policy_check", clientProfile, "policy", "check policy", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        var requestedTool = NormalizeToolName(ReadString(args, "tool_name"));
        var decision = EvaluatePolicyCheck(args, requestedTool, clientProfile);
        audit.Record(
            "policy_check",
            clientProfile,
            IsKnownTool(requestedTool) ? requestedTool : "policy",
            IsKnownTool(requestedTool) ? SafeAction(ReadPolicyAction(args)) : "unknown tool",
            "ok");
        return ToolText(new
        {
            tool_name = IsKnownTool(requestedTool) ? requestedTool : "unknown",
            client_profile = clientProfile,
            allowed = decision.Allowed,
            needs_approval = decision.NeedsApproval,
            reason = decision.Reason,
            prompt_shown = false,
            secret_visible_to_model = false
        });
    }

    private object ConfigSummary(JsonElement args)
    {
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("config_summary", clientProfile))
        {
            audit.Record("config_summary", clientProfile, "config", "read config summary", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        return ToolText(summary.Build(clientProfile));
    }

    private object ForgetCredential(JsonElement args)
    {
        var alias = ReadString(args, "alias");
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("forget_credential", clientProfile))
        {
            audit.Record("forget_credential", clientProfile, alias, "delete credential alias", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        if (!IsConfiguredCredentialAlias(alias))
        {
            audit.Record("forget_credential", clientProfile, "credential", "delete unknown credential alias", "unknown", "credential alias is not configured");
            return ToolText(new
            {
                status = "unknown",
                configured = false,
                secret_visible_to_model = false
            });
        }

        var existed = credentials.Forget(alias);
        audit.Record("forget_credential", clientProfile, alias, "delete credential alias", existed ? "forgotten" : "missing");
        return ToolText(new
        {
            alias,
            status = existed ? "forgotten" : "missing",
            configured = true,
            secret_visible_to_model = false
        });
    }

    private object AuditTail(JsonElement args)
    {
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("audit_tail", clientProfile))
        {
            audit.Record("audit_tail", clientProfile, "audit", "read audit tail", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        var limit = ReadInt(args, "limit", 20);
        return ToolText(new
        {
            entries = auditReader.Tail(limit)
        });
    }

    private object SessionList(JsonElement args)
    {
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("session_list", clientProfile))
        {
            audit.Record("session_list", clientProfile, "sessions", "list sessions", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        return ToolText(new
        {
            sessions = sshSessions.List(clientProfile),
            secret_visible_to_model = false
        });
    }

    private object SessionClose(JsonElement args)
    {
        var sessionId = ReadString(args, "session_id");
        var clientProfile = ReadClientProfile(args);
        if (!IsToolAllowedForProfile("session_close", clientProfile))
        {
            audit.Record("session_close", clientProfile, sessionId, "close session", "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
        }

        var target = sshSessions.TryGetInfo(sessionId, clientProfile, out var session) ? session.RouteId : "session";
        var closed = sshSessions.Close(sessionId, clientProfile);
        audit.Record("session_close", clientProfile, target, "close session", closed ? "closed" : "missing");
        if (!closed)
        {
            return ToolText(new
            {
                status = "missing",
                secret_visible_to_model = false
            });
        }

        return ToolText(new
        {
            session_id = sessionId,
            status = "closed",
            secret_visible_to_model = false
        });
    }

    private bool IsToolAllowedForProfile(string toolName, string clientProfile)
    {
        var profile = config.ClientProfiles.FirstOrDefault(profile =>
            profile.Id.Equals(clientProfile, StringComparison.OrdinalIgnoreCase));

        return profile is not null &&
            (profile.AllowedTools.Count == 0 ||
             profile.AllowedTools.Contains(toolName, StringComparer.OrdinalIgnoreCase));
    }

    private string ReadClientProfile(JsonElement args)
    {
        var requested = ReadOptionalString(args, "client_profile");
        if (!string.IsNullOrWhiteSpace(requested) &&
            !requested.Equals(mcpClientProfile, StringComparison.OrdinalIgnoreCase))
        {
            throw new ClientProfileLockException(mcpClientProfile);
        }

        return mcpClientProfile;
    }

    private static IReadOnlyDictionary<string, object?> ReadParameters(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object ||
            !args.TryGetProperty("params", out var parameters) ||
            parameters.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return new Dictionary<string, object?>();
        }

        if (parameters.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("params must be an object.");
        }

        var result = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in parameters.EnumerateObject())
        {
            result[property.Name] = ConvertJsonValue(property.Value);
        }

        return result;
    }

    private static object? ConvertJsonValue(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number when value.TryGetInt64(out var integer) => integer,
            JsonValueKind.Number when value.TryGetDecimal(out var number) => number,
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => throw new InvalidOperationException("DB params may only contain string, number, boolean, or null values.")
        };
    }

    private static string ReadString(JsonElement args, string name, string? defaultValue = null)
    {
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty(name, out var value) &&
            value.ValueKind == JsonValueKind.String)
        {
            return value.GetString() ?? "";
        }

        if (defaultValue is not null)
        {
            return defaultValue;
        }

        throw new InvalidOperationException($"Missing required argument: {name}");
    }

    private static string? ReadOptionalString(JsonElement args, string name)
    {
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty(name, out var value) &&
            value.ValueKind == JsonValueKind.String)
        {
            return value.GetString();
        }

        return null;
    }

    private static int ReadInt(JsonElement args, string name, int defaultValue)
    {
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty(name, out var value) &&
            value.ValueKind == JsonValueKind.Number &&
            value.TryGetInt32(out var integer))
        {
            return integer;
        }

        return defaultValue;
    }

    private static bool ReadBool(JsonElement args, string name, bool defaultValue)
    {
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty(name, out var value) &&
            value.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            return value.GetBoolean();
        }

        return defaultValue;
    }

    private static IReadOnlyList<string> ReadStringList(JsonElement args, string name, IReadOnlyList<string> defaultValue)
    {
        if (args.ValueKind != JsonValueKind.Object ||
            !args.TryGetProperty(name, out var value) ||
            value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return defaultValue;
        }

        if (value.ValueKind == JsonValueKind.String)
        {
            return value.GetString()?
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .ToList() ?? [];
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException($"{name} must be an array of strings.");
        }

        var items = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                throw new InvalidOperationException($"{name} must be an array of strings.");
            }

            var text = item.GetString();
            if (!string.IsNullOrWhiteSpace(text))
            {
                items.Add(text.Trim());
            }
        }

        return items;
    }

    private PolicyDecision EvaluatePolicyCheck(JsonElement args, string requestedTool, string clientProfile)
    {
        if (!IsKnownTool(requestedTool))
        {
            return PolicyDecision.Deny("unknown tool");
        }

        if (!IsToolAllowedForProfile(requestedTool, clientProfile))
        {
            return PolicyDecision.Deny("tool is not allowed for this client profile");
        }

        if (requestedTool == "ssh_open_session")
        {
            return policy.Evaluate(BuildPolicyRequest(args, "route_test", clientProfile));
        }

        if (requestedTool is "ssh_run" or "route_test" or "db_query" or "browser_login")
        {
            return policy.Evaluate(BuildPolicyRequest(args, requestedTool, clientProfile));
        }

        return PolicyDecision.Allow();
    }

    private static ToolRequest BuildPolicyRequest(JsonElement args, string requestedTool, string clientProfile)
    {
        var routeId = ReadOptionalString(args, "route_id");
        var connectionId = ReadOptionalString(args, "connection_id");
        var browserTargetId = ReadOptionalString(args, "target_id");
        var command = ReadOptionalString(args, "command") ?? "";
        var sql = ReadOptionalString(args, "sql") ?? "";

        return new ToolRequest(
            requestedTool,
            clientProfile,
            RouteId: routeId,
            ConnectionId: connectionId,
            BrowserTargetId: browserTargetId,
            Command: command,
            Sql: sql);
    }

    private static string ReadPolicyAction(JsonElement args)
    {
        return ReadOptionalString(args, "command") ??
            ReadOptionalString(args, "sql") ??
            ReadOptionalString(args, "route_id") ??
            ReadOptionalString(args, "connection_id") ??
            ReadOptionalString(args, "target_id") ??
            "policy check";
    }

    private static string NormalizeToolName(string toolName) => toolName.Trim().ToLowerInvariant();

    private static DbEngine ParseDbEngine(string value)
    {
        return value.Equals("postgres", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("postgresql", StringComparison.OrdinalIgnoreCase)
            ? DbEngine.Postgres
            : value.Equals("mysql", StringComparison.OrdinalIgnoreCase) ||
              value.Equals("mariadb", StringComparison.OrdinalIgnoreCase)
                ? DbEngine.MySql
                : throw new InvalidOperationException("engine must be postgres or mysql.");
    }

    private static int DefaultDbPort(DbEngine engine) => engine == DbEngine.Postgres ? 5432 : 3306;

    private static bool IsKnownTool(string toolName)
    {
        return toolName is "ssh_run" or "ssh_register" or "ssh_open_session" or "session_list" or "session_close" or
            "browser_login" or "browser_register" or "db_query" or "db_register" or "route_test" or "policy_check" or
            "credential_status" or "forget_credential" or "config_summary" or "audit_tail";
    }

    private static string ToolName(object tool) =>
        tool.GetType().GetProperty("name")?.GetValue(tool)?.ToString() ?? "";

    private bool IsConfiguredCredentialAlias(string alias) =>
        config.Credentials.Any(credential => credential.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase));

    private bool IsConfiguredRoute(string routeId) =>
        config.Routes.Any(route => route.Id.Equals(routeId, StringComparison.OrdinalIgnoreCase));

    private bool IsConfiguredDbTarget(string connectionId) =>
        config.DbTargets.Any(target => target.Id.Equals(connectionId, StringComparison.OrdinalIgnoreCase));

    private bool IsConfiguredBrowserTarget(string targetId) =>
        config.BrowserTargets.Any(target => target.Id.Equals(targetId, StringComparison.OrdinalIgnoreCase));

    private bool EnsureAllowed(PolicyDecision decision, string clientProfile, string title, string target, string action)
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

        var approved = approval.Approve(title, target, safeAction, reason);
        if (approved)
        {
            approvalCache.Remember(clientProfile, title, target, safeAction, reason);
        }

        return approved;
    }

    private static string SafeAction(string action)
    {
        action = action.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return action.Length <= 500 ? action : action[..500] + "...";
    }

    private static object ToolText(object value)
    {
        return new
        {
            content = new[]
            {
                new
                {
                    type = "text",
                    text = JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                }
            }
        };
    }

    private static object ToolError(string code, object? data = null)
    {
        return new
        {
            isError = true,
            content = new[]
            {
                new
                {
                    type = "text",
                    text = JsonSerializer.Serialize(new { code, data }, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                }
            }
        };
    }
}

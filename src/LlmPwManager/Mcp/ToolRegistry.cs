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
    string mcpClientProfile)
{
    public IReadOnlyList<object> ListTools()
    {
        object[] tools =
        [
        new
        {
            name = "ssh_run",
            description = "Run an approved command over a configured SSH route without exposing credentials.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    route_id = new { type = "string" },
                    session_id = new { type = "string" },
                    command = new { type = "string" },
                    purpose = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "command", "purpose" }
            }
        },
        new
        {
            name = "ssh_open_session",
            description = "Open a reusable SSH route session and return an opaque session_id. Secrets remain isolated in the manager process.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    route_id = new { type = "string" },
                    purpose = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "route_id", "purpose" }
            }
        },
        new
        {
            name = "session_list",
            description = "List active broker-managed sessions without exposing credentials.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    client_profile = new { type = "string" }
                }
            }
        },
        new
        {
            name = "session_close",
            description = "Close an active broker-managed session by opaque session_id.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    session_id = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "session_id" }
            }
        },
        new
        {
            name = "browser_login",
            description = "Open a configured isolated browser login target and fill credentials without exposing the password to the model.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    target_id = new { type = "string" },
                    purpose = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "target_id", "purpose" }
            }
        },
        new
        {
            name = "db_query",
            description = "Run an approved SQL query through a configured DB connection and optional SSH route or SSH session.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    connection_id = new { type = "string" },
                    session_id = new { type = "string" },
                    sql = new { type = "string" },
                    @params = new { type = "object", additionalProperties = true },
                    purpose = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "connection_id", "sql", "purpose" }
            }
        },
        new
        {
            name = "route_test",
            description = "Test a configured SSH route without returning credentials.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    route_id = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "route_id" }
            }
        },
        new
        {
            name = "policy_check",
            description = "Check whether a tool request would be allowed, denied, or require approval without executing it or prompting the user.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    tool_name = new { type = "string" },
                    route_id = new { type = "string" },
                    connection_id = new { type = "string" },
                    target_id = new { type = "string" },
                    command = new { type = "string" },
                    sql = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "tool_name" }
            }
        },
        new
        {
            name = "credential_status",
            description = "Return whether a configured credential alias is registered. Unknown aliases are not queried. The secret value is never returned.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    alias = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "alias" }
            }
        },
        new
        {
            name = "forget_credential",
            description = "Delete a stored configured credential by alias so the next operation prompts the user again. Unknown aliases are not deleted. The secret value is never returned.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    alias = new { type = "string" },
                    client_profile = new { type = "string" }
                },
                required = new[] { "alias" }
            }
        },
        new
        {
            name = "config_summary",
            description = "Return configured client profiles, routes, targets, and credential registration status without exposing secrets.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    client_profile = new { type = "string" }
                }
            }
        },
        new
        {
            name = "audit_tail",
            description = "Return recent secret-free audit log entries for allowed client profiles.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    limit = new { type = "integer", minimum = 1, maximum = 500 },
                    client_profile = new { type = "string" }
                }
            }
        }
        ];

        return tools
            .Where(tool => IsToolAllowedForProfile(ToolName(tool), mcpClientProfile))
            .ToList();
    }

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
                "ssh_open_session" => await SshOpenSessionAsync(args, cancellationToken),
                "session_list" => SessionList(args),
                "session_close" => SessionClose(args),
                "browser_login" => await BrowserLoginAsync(args, cancellationToken),
                "db_query" => await DbQueryAsync(args, cancellationToken),
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

    private async Task<object> SshRunAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var routeId = ReadOptionalString(args, "route_id");
        var sessionId = ReadOptionalString(args, "session_id");
        var command = ReadString(args, "command");
        var clientProfile = ReadClientProfile(args);

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
            audit.Record("ssh_open_session", clientProfile, routeId, SafeAction(purpose), "denied", "tool is not allowed for this client profile");
            return ToolError("policy_denied", new { reason = "tool is not allowed for this client profile", needsApproval = false });
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
            var target = config.DbTargets.FirstOrDefault(dbTarget =>
                dbTarget.Id.Equals(connectionId, StringComparison.OrdinalIgnoreCase));
            if (target is null)
            {
                throw new InvalidOperationException($"Unknown DB connection: {connectionId}");
            }

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

    private async Task<object> BrowserLoginAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var targetId = ReadString(args, "target_id");
        var purpose = ReadString(args, "purpose");
        var clientProfile = ReadClientProfile(args);
        var target = config.BrowserTargets.FirstOrDefault(browserTarget =>
            browserTarget.Id.Equals(targetId, StringComparison.OrdinalIgnoreCase));
        if (target is null)
        {
            throw new InvalidOperationException($"Unknown browser target: {targetId}");
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

    private async Task<object> RouteTestAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var routeId = ReadString(args, "route_id");
        var clientProfile = ReadClientProfile(args);
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

    private static bool IsKnownTool(string toolName)
    {
        return toolName is "ssh_run" or "ssh_open_session" or "session_list" or "session_close" or
            "browser_login" or "db_query" or "route_test" or "policy_check" or
            "credential_status" or "forget_credential" or "config_summary" or "audit_tail";
    }

    private static string ToolName(object tool) =>
        tool.GetType().GetProperty("name")?.GetValue(tool)?.ToString() ?? "";

    private bool IsConfiguredCredentialAlias(string alias) =>
        config.Credentials.Any(credential => credential.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase));

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

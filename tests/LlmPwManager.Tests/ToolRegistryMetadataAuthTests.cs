using System.Text.Json;
using LlmPwManager.Audit;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Mcp;
using LlmPwManager.Policy;
using LlmPwManager.Ssh;
using LlmPwManager.Ui;

namespace LlmPwManager.Tests;

public sealed class ToolRegistryMetadataAuthTests
{
    [Fact]
    public async Task UnknownToolDoesNotEchoRequestedName()
    {
        var tools = CreateRegistry(["credential_status"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "Password=super-secret",
              "arguments": {}
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"isError\":true", json);
        Assert.Contains("unknown_tool", json);
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public void ListToolsOnlyReturnsToolsAllowedForLockedProfile()
    {
        var tools = CreateRegistry(["credential_status", "policy_check"]);

        var json = JsonSerializer.Serialize(tools.ListTools(), new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"name\":\"credential_status\"", json);
        Assert.Contains("\"name\":\"policy_check\"", json);
        Assert.DoesNotContain("\"name\":\"ssh_run\"", json);
        Assert.DoesNotContain("\"name\":\"db_query\"", json);
        Assert.DoesNotContain("\"name\":\"browser_login\"", json);
    }

    [Fact]
    public async Task CredentialStatusRespectsClientProfileAllowedTools()
    {
        var tools = CreateRegistry(["config_summary"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "credential_status",
              "arguments": {
                "alias": "prod-secret",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"isError\":true", json);
        Assert.Contains("policy_denied", json);
    }

    [Fact]
    public async Task MetadataToolRejectsUnknownClientProfileBeforePolicyEvaluation()
    {
        var tools = CreateRegistry(["credential_status"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "credential_status",
              "arguments": {
                "alias": "prod-secret",
                "client_profile": "missing-profile"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"isError\":true", json);
        Assert.Contains("client_profile_locked", json);
        Assert.DoesNotContain("missing-profile", json);
    }

    [Fact]
    public async Task ConfigSummaryRespectsClientProfileAllowedTools()
    {
        var tools = CreateRegistry(["credential_status"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "config_summary",
              "arguments": {
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"isError\":true", json);
        Assert.Contains("policy_denied", json);
    }

    [Fact]
    public async Task ToolCallCannotEscalateAboveLockedMcpClientProfile()
    {
        var tools = CreateRegistry(["credential_status"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "credential_status",
              "arguments": {
                "alias": "prod-secret",
                "client_profile": "full"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var payload = ReadToolText(result);

        Assert.Contains("\"isError\":true", json);
        Assert.Contains("client_profile_locked", json);
        Assert.Equal("restricted", payload.GetProperty("data").GetProperty("client_profile").GetString());
        Assert.DoesNotContain("\"client_profile\":\"full\"", json);
    }

    [Fact]
    public async Task CredentialStatusDoesNotTouchStoreForUnconfiguredAlias()
    {
        var (tools, store) = CreateRegistryWithStore(["credential_status"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "credential_status",
              "arguments": {
                "alias": "not-configured-password=hunter2",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal("unknown", payload.GetProperty("status").GetString());
        Assert.False(payload.GetProperty("configured").GetBoolean());
        Assert.False(payload.GetProperty("secret_visible_to_model").GetBoolean());
        Assert.DoesNotContain("not-configured-password", json);
        Assert.DoesNotContain("hunter2", json);
        Assert.Equal(0, store.ExistsCalls);
    }

    [Fact]
    public async Task ForgetCredentialDoesNotTouchStoreForUnconfiguredAlias()
    {
        var (tools, store) = CreateRegistryWithStore(["forget_credential"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "forget_credential",
              "arguments": {
                "alias": "not-configured-password=hunter2",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal("unknown", payload.GetProperty("status").GetString());
        Assert.False(payload.GetProperty("configured").GetBoolean());
        Assert.False(payload.GetProperty("secret_visible_to_model").GetBoolean());
        Assert.DoesNotContain("not-configured-password", json);
        Assert.DoesNotContain("hunter2", json);
        Assert.Equal(0, store.ExistsCalls);
        Assert.Equal(0, store.DeleteCalls);
    }

    [Fact]
    public async Task CredentialStatusChecksStoreForConfiguredAlias()
    {
        var (tools, store) = CreateRegistryWithStore(["credential_status"], existingAliases: ["prod-secret"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "credential_status",
              "arguments": {
                "alias": "prod-secret",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);

        Assert.Equal("registered", payload.GetProperty("status").GetString());
        Assert.True(payload.GetProperty("configured").GetBoolean());
        Assert.Equal(1, store.ExistsCalls);
    }

    [Fact]
    public async Task PolicyCheckReturnsDecisionWithoutPrompt()
    {
        var tools = CreateRegistry(["policy_check", "ssh_run"], includeSshPolicy: true);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "policy_check",
              "arguments": {
                "tool_name": "ssh_run",
                "route_id": "prod",
                "command": "uptime",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);

        Assert.True(payload.GetProperty("allowed").GetBoolean());
        Assert.False(payload.GetProperty("prompt_shown").GetBoolean());
        Assert.False(payload.GetProperty("secret_visible_to_model").GetBoolean());
    }

    [Fact]
    public async Task PolicyCheckReportsDeniedDecisionWithoutPrompt()
    {
        var tools = CreateRegistry(["policy_check", "ssh_run"], includeSshPolicy: true);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "policy_check",
              "arguments": {
                "tool_name": "ssh_run",
                "route_id": "prod",
                "command": "rm -rf /tmp/example",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);

        Assert.False(payload.GetProperty("allowed").GetBoolean());
        Assert.False(payload.GetProperty("prompt_shown").GetBoolean());
    }

    [Fact]
    public async Task PolicyCheckDoesNotEchoUnknownToolName()
    {
        var tools = CreateRegistry(["policy_check"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "policy_check",
              "arguments": {
                "tool_name": "password=super-secret",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal("unknown", payload.GetProperty("tool_name").GetString());
        Assert.False(payload.GetProperty("allowed").GetBoolean());
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task MissingSessionErrorsDoNotEchoRequestedSessionId()
    {
        using var sessions = CreateEmptySessionManager();
        var tools = CreateRegistryWithStore(["ssh_run"], sshSessions: sessions).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_run",
              "arguments": {
                "session_id": "password=super-secret",
                "command": "uptime",
                "purpose": "read status",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("session_not_found", json);
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task ClosingMissingSessionDoesNotEchoRequestedSessionId()
    {
        using var sessions = CreateEmptySessionManager();
        var tools = CreateRegistryWithStore(["session_close"], sshSessions: sessions).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "session_close",
              "arguments": {
                "session_id": "password=super-secret",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal("missing", payload.GetProperty("status").GetString());
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task AuditDoesNotEchoUnknownCredentialAliasOrToolName()
    {
        var (tools, _, auditPath) = CreateRegistryWithAudit(["credential_status", "policy_check"]);

        await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "credential_status",
              "arguments": {
                "alias": "not-configured-password=hunter2",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);
        await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "policy_check",
              "arguments": {
                "tool_name": "password=hunter2",
                "command": "token=hunter2",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var auditJson = string.Join("\n", new AuditLogReader(auditPath).Tail(10).Select(entry =>
            JsonSerializer.Serialize(entry, new JsonSerializerOptions(JsonSerializerDefaults.Web))));

        Assert.Contains("\"target\":\"credential\"", auditJson);
        Assert.Contains("\"target\":\"policy\"", auditJson);
        Assert.Contains("\"action\":\"unknown tool\"", auditJson);
        Assert.DoesNotContain("not-configured-password", auditJson);
        Assert.DoesNotContain("hunter2", auditJson);
    }

    [Fact]
    public async Task AuditDoesNotEchoMissingSessionId()
    {
        using var sessions = CreateEmptySessionManager();
        var (tools, _, auditPath) = CreateRegistryWithAudit(["session_close"], sshSessions: sessions);

        await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "session_close",
              "arguments": {
                "session_id": "password=hunter2",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var entry = new AuditLogReader(auditPath).Tail(1).Single();

        Assert.Equal("session", entry.Target);
        Assert.DoesNotContain("hunter2", JsonSerializer.Serialize(entry, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }

    private static ToolRegistry CreateRegistry(IReadOnlyList<string> allowedTools, bool includeSshPolicy = false)
    {
        return CreateRegistryWithStore(allowedTools, includeSshPolicy).Tools;
    }

    private static (ToolRegistry Tools, FakeCredentialStore Store) CreateRegistryWithStore(
        IReadOnlyList<string> allowedTools,
        bool includeSshPolicy = false,
        IReadOnlyList<string>? existingAliases = null,
        SshSessionManager? sshSessions = null)
    {
        var (tools, store, _) = CreateRegistryWithAudit(allowedTools, includeSshPolicy, existingAliases, sshSessions);
        return (tools, store);
    }

    private static (ToolRegistry Tools, FakeCredentialStore Store, string AuditPath) CreateRegistryWithAudit(
        IReadOnlyList<string> allowedTools,
        bool includeSshPolicy = false,
        IReadOnlyList<string>? existingAliases = null,
        SshSessionManager? sshSessions = null)
    {
        var config = new AppConfig
        {
            DefaultClientProfile = "restricted",
            ClientProfiles =
            [
                new() { Id = "restricted", Permission = PermissionProfile.Limited, AllowedTools = allowedTools.ToList() },
                new() { Id = "full", Permission = PermissionProfile.Full, AllowedTools = [] }
            ],
            Credentials =
            [
                new() { Alias = "prod-secret", Label = "Prod secret", UserName = "deploy" }
            ]
        };
        if (includeSshPolicy)
        {
            config.SshTargets.Add(new SshTarget
            {
                Id = "prod",
                Host = "prod.example.com",
                UserName = "deploy",
                CredentialAlias = "prod-secret"
            });
            config.Routes.Add(new RouteDefinition
            {
                Id = "prod",
                SshChain = ["prod"]
            });
            config.Policies.Add(new PolicyRule
            {
                Id = "safe-ssh",
                Tools = ["ssh_run"],
                RouteIds = ["prod"],
                CommandPrefixes = ["uptime"],
                MinPermission = PermissionProfile.Limited
            });
        }

        var store = new FakeCredentialStore(existingAliases ?? []);
        var resolver = new CredentialResolver(store, new FakeCredentialPrompt(), maxAttempts: 1);
        var auditPath = Path.Combine(Path.GetTempPath(), "llm-pw-manager-tests", Guid.NewGuid().ToString("N"), "audit.jsonl");
        var audit = new AuditLogger(auditPath);

        var tools = new ToolRegistry(
            config,
            new PolicyEvaluator(config),
            null!,
            new ApprovalCache(),
            audit,
            new AuditLogReader(auditPath),
            resolver,
            null!,
            sshSessions!,
            null!,
            null!,
            new ConfigSummary(config, store),
            "restricted");
        return (tools, store, auditPath);
    }

    private static SshSessionManager CreateEmptySessionManager()
    {
        return new SshSessionManager(
            (routeId, _) => Task.FromResult(new RouteConnection(routeId, [], [], [])),
            (_, _, _) => Task.FromResult(new SshRunResult(0, "", "")),
            TimeSpan.FromMinutes(30),
            () => DateTimeOffset.UtcNow);
    }

    private sealed class FakeCredentialStore(IReadOnlyList<string> existingAliases) : ICredentialStore
    {
        public int ExistsCalls { get; private set; }
        public int DeleteCalls { get; private set; }

        public bool Exists(string alias)
        {
            ExistsCalls++;
            return existingAliases.Contains(alias, StringComparer.OrdinalIgnoreCase);
        }

        public string? GetSecret(string alias) => null;
        public void SaveSecret(string alias, string secret) { }

        public void DeleteSecret(string alias)
        {
            DeleteCalls++;
        }
    }

    private sealed class FakeCredentialPrompt : ICredentialPrompt
    {
        public string? RequestPassword(string alias, string label, string userName, string reason) => null;
    }

    private static JsonElement ReadToolText(object result)
    {
        var outerJson = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var outer = JsonDocument.Parse(outerJson);
        var text = outer.RootElement.GetProperty("content")[0].GetProperty("text").GetString() ?? "{}";
        using var inner = JsonDocument.Parse(text);
        return inner.RootElement.Clone();
    }
}

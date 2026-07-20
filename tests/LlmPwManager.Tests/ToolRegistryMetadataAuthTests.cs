using System.Text.Json;
using LlmPwManager.Audit;
using LlmPwManager.Browser;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Db;
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
    public void ListToolsIncludesLLMUsageGuidanceInDescriptions()
    {
        var tools = CreateRegistry(["config_summary", "credential_status", "ssh_run", "ssh_sudo_run", "db_query", "route_test"]);

        var json = JsonSerializer.Serialize(tools.ListTools(), new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("Use this first when the user asks what SSH routes", json);
        Assert.Contains("Use this instead of raw ssh", json);
        Assert.Contains("Use this instead of asking for a sudo password", json);
        Assert.Contains("Use this instead of raw psql/mysql", json);
        Assert.Contains("Use this before asking the user about credentials", json);
        Assert.Contains("Get available route ids from config_summary", json);
        Assert.Contains("Why this SSH command is needed", json);
    }

    [Fact]
    public void DefaultSudoCredentialAliasUsesLeafTargetAndSshUser()
    {
        var alias = ToolRegistry.BuildDefaultSudoCredentialAlias(new SshTarget
        {
            Id = "app-02",
            UserName = "deploy"
        });

        Assert.Equal("app-02-deploy-sudo-password", alias);
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
    public async Task SshRegisterRequiresAllowedTool()
    {
        var tools = CreateRegistry(["credential_status"]);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_register",
              "arguments": {
                "route_id": "prod",
                "host": "prod.example.com",
                "user_name": "deploy",
                "purpose": "register production ssh",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"isError\":true", json);
        Assert.Contains("policy_denied", json);
    }

    [Fact]
    public async Task SshRegisterPromptsApprovalAndReturnsSecretFreeResult()
    {
        var registration = new FakeSshRegistrationService();
        var approval = new FakeApprovalPrompt(approve: true);
        var tools = CreateRegistry(["ssh_register"], approvalPrompt: approval, sshRegistration: registration);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_register",
              "arguments": {
                "route_id": "prod",
                "host": "prod.example.com",
                "port": 2222,
                "user_name": "deploy",
                "purpose": "register production ssh",
                "command_prefixes": ["uptime"],
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal("registered", payload.GetProperty("status").GetString());
        Assert.Equal("prod", payload.GetProperty("route_id").GetString());
        Assert.False(payload.GetProperty("secret_visible_to_model").GetBoolean());
        Assert.Equal(1, approval.Calls);
        Assert.Equal("prod.example.com", registration.Requests.Single().Host);
        Assert.Equal(2222, registration.Requests.Single().Port);
        Assert.Equal("prod", registration.Requests.Single().TargetId);
        Assert.Null(registration.Requests.Single().ViaRouteId);
        Assert.Contains("uptime", registration.Requests.Single().CommandPrefixes);
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task SshRegisterCanDescribeNestedRouteRegistration()
    {
        var registration = new FakeSshRegistrationService();
        var approval = new FakeApprovalPrompt(approve: true);
        var tools = CreateRegistryWithStore(["ssh_register"], includeSshPolicy: true, approvalPrompt: approval, sshRegistration: registration).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_register",
              "arguments": {
                "route_id": "bastion-to-app",
                "target_id": "app",
                "via_route_id": "prod",
                "host": "10.0.0.12",
                "port": 22,
                "user_name": "deploy",
                "purpose": "register inner app host through bastion",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);

        Assert.Equal("registered", payload.GetProperty("status").GetString());
        Assert.Equal("bastion-to-app", payload.GetProperty("route_id").GetString());
        Assert.Equal("app", payload.GetProperty("target_id").GetString());
        Assert.Equal("prod", payload.GetProperty("via_route_id").GetString());
        Assert.Equal(1, approval.Calls);
        Assert.Equal("prod", registration.Requests.Single().ViaRouteId);
        Assert.Equal("app", registration.Requests.Single().TargetId);
    }

    [Fact]
    public async Task SshRegisterDoesNotCallRegistrationWhenUserDenies()
    {
        var registration = new FakeSshRegistrationService();
        var approval = new FakeApprovalPrompt(approve: false);
        var tools = CreateRegistry(["ssh_register"], approvalPrompt: approval, sshRegistration: registration);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_register",
              "arguments": {
                "route_id": "prod",
                "host": "prod.example.com",
                "user_name": "deploy",
                "purpose": "register production ssh",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"isError\":true", json);
        Assert.Contains("user_denied", json);
        Assert.Empty(registration.Requests);
    }

    [Fact]
    public async Task DbRegisterPromptsApprovalAndReturnsSecretFreeResult()
    {
        var registration = new FakeDbRegistrationService();
        var approval = new FakeApprovalPrompt(approve: true);
        var tools = CreateRegistry(["db_register"], approvalPrompt: approval, dbRegistration: registration);

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "db_register",
              "arguments": {
                "connection_id": "payments",
                "engine": "postgres",
                "host": "db.example.com",
                "database": "payments",
                "user_name": "readonly",
                "purpose": "register reporting db",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);

        Assert.Equal("registered", payload.GetProperty("status").GetString());
        Assert.Equal("payments", payload.GetProperty("connection_id").GetString());
        Assert.False(payload.GetProperty("secret_visible_to_model").GetBoolean());
        Assert.Equal(1, approval.Calls);
        Assert.Equal("db.example.com", registration.Requests.Single().Host);
        Assert.Equal(DbEngine.Postgres, registration.Requests.Single().Engine);
    }

    [Fact]
    public async Task BrowserRegisterPromptsApprovalAndReturnsSecretFreeResult()
    {
        var registration = new FakeBrowserRegistrationService();
        var approval = new FakeApprovalPrompt(approve: true);
        var tools = CreateRegistry(["browser_register"], approvalPrompt: approval, browserRegistration: registration);

        var result = await tools.CallAsync(JsonDocument.Parse("""
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
                "purpose": "register admin login",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);

        Assert.Equal("registered", payload.GetProperty("status").GetString());
        Assert.Equal("admin-console", payload.GetProperty("target_id").GetString());
        Assert.False(payload.GetProperty("secret_visible_to_model").GetBoolean());
        Assert.Equal(1, approval.Calls);
        Assert.Equal("https://admin.example.com/login", registration.Requests.Single().LoginUrl);
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
    public async Task MissingSudoSessionErrorsDoNotEchoRequestedSessionId()
    {
        using var sessions = CreateEmptySessionManager();
        var tools = CreateRegistryWithStore(["ssh_sudo_run"], sshSessions: sessions).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_sudo_run",
              "arguments": {
                "session_id": "password=super-secret",
                "command": "whoami",
                "purpose": "check root user",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("session_not_found", json);
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task UnknownSudoRouteSuggestsRegistrationWithoutEchoingRouteId()
    {
        var tools = CreateRegistryWithStore(["ssh_sudo_run"]).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_sudo_run",
              "arguments": {
                "route_id": "password=super-secret",
                "command": "whoami",
                "purpose": "check root user",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("ssh_route_not_registered", json);
        Assert.Contains("ssh_register", json);
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task SudoRunWithoutPolicyIsDeniedBeforeExecution()
    {
        var tools = CreateRegistryWithStore(["ssh_sudo_run"], includeSshPolicy: true).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_sudo_run",
              "arguments": {
                "route_id": "prod",
                "command": "whoami",
                "purpose": "check root user",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("policy_denied", json);
        Assert.Contains("no matching policy rule", json);
    }

    [Fact]
    public async Task UnknownSshRouteSuggestsRegistrationWithoutEchoingRouteId()
    {
        var tools = CreateRegistryWithStore(["ssh_run"]).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "ssh_run",
              "arguments": {
                "route_id": "password=super-secret",
                "command": "uptime",
                "purpose": "read status",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("ssh_route_not_registered", json);
        Assert.Contains("ssh_register", json);
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task UnknownRouteTestSuggestsRegistrationWithoutPrompting()
    {
        var tools = CreateRegistryWithStore(["route_test"]).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "route_test",
              "arguments": {
                "route_id": "password=super-secret",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var payload = ReadToolText(result);
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal("ssh_route_not_registered", payload.GetProperty("code").GetString());
        Assert.True(payload.GetProperty("data").GetProperty("needs_user_registration").GetBoolean());
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task UnknownDbConnectionSuggestsRegistrationWithoutEchoingConnectionId()
    {
        var tools = CreateRegistryWithStore(["db_query"]).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "db_query",
              "arguments": {
                "connection_id": "password=super-secret",
                "sql": "select 1",
                "purpose": "read db",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("db_connection_not_registered", json);
        Assert.Contains("db_register", json);
        Assert.DoesNotContain("super-secret", json);
    }

    [Fact]
    public async Task UnknownBrowserTargetSuggestsRegistrationWithoutEchoingTargetId()
    {
        var tools = CreateRegistryWithStore(["browser_login"]).Tools;

        var result = await tools.CallAsync(JsonDocument.Parse("""
            {
              "name": "browser_login",
              "arguments": {
                "target_id": "password=super-secret",
                "purpose": "login",
                "client_profile": "restricted"
              }
            }
            """).RootElement, CancellationToken.None);

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("browser_target_not_registered", json);
        Assert.Contains("browser_register", json);
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

    private static ToolRegistry CreateRegistry(
        IReadOnlyList<string> allowedTools,
        bool includeSshPolicy = false,
        IApprovalPrompt? approvalPrompt = null,
        ISshRegistrationService? sshRegistration = null,
        IDbRegistrationService? dbRegistration = null,
        IBrowserRegistrationService? browserRegistration = null)
    {
        return CreateRegistryWithStore(allowedTools, includeSshPolicy, approvalPrompt: approvalPrompt, sshRegistration: sshRegistration, dbRegistration: dbRegistration, browserRegistration: browserRegistration).Tools;
    }

    private static (ToolRegistry Tools, FakeCredentialStore Store) CreateRegistryWithStore(
        IReadOnlyList<string> allowedTools,
        bool includeSshPolicy = false,
        IReadOnlyList<string>? existingAliases = null,
        SshSessionManager? sshSessions = null,
        IApprovalPrompt? approvalPrompt = null,
        ISshRegistrationService? sshRegistration = null,
        IDbRegistrationService? dbRegistration = null,
        IBrowserRegistrationService? browserRegistration = null)
    {
        var (tools, store, _) = CreateRegistryWithAudit(allowedTools, includeSshPolicy, existingAliases, sshSessions, approvalPrompt, sshRegistration, dbRegistration, browserRegistration);
        return (tools, store);
    }

    private static (ToolRegistry Tools, FakeCredentialStore Store, string AuditPath) CreateRegistryWithAudit(
        IReadOnlyList<string> allowedTools,
        bool includeSshPolicy = false,
        IReadOnlyList<string>? existingAliases = null,
        SshSessionManager? sshSessions = null,
        IApprovalPrompt? approvalPrompt = null,
        ISshRegistrationService? sshRegistration = null,
        IDbRegistrationService? dbRegistration = null,
        IBrowserRegistrationService? browserRegistration = null)
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
            approvalPrompt ?? new FakeApprovalPrompt(approve: true),
            new ApprovalCache(),
            audit,
            new AuditLogReader(auditPath),
            resolver,
            null!,
            sshSessions!,
            null!,
            null!,
            new ConfigSummary(config, store),
            "restricted",
            sshRegistration,
            dbRegistration,
            browserRegistration);
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

    private sealed class FakeApprovalPrompt(bool approve) : IApprovalPrompt
    {
        public int Calls { get; private set; }

        public bool Approve(string title, string target, string action, string reason)
        {
            Calls++;
            return approve;
        }
    }

    private sealed class FakeSshRegistrationService : ISshRegistrationService
    {
        public List<SshRegistrationRequest> Requests { get; } = [];

        public Task<SshRegistrationResult> RegisterPasswordAsync(SshRegistrationRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(new SshRegistrationResult("registered", request.RouteId, request.TargetId, $"{request.RouteId}-password", true));
        }
    }

    private sealed class FakeDbRegistrationService : IDbRegistrationService
    {
        public List<DbRegistrationRequest> Requests { get; } = [];

        public Task<DbRegistrationResult> RegisterAsync(DbRegistrationRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(new DbRegistrationResult("registered", request.ConnectionId, $"{request.ConnectionId}-password", true));
        }
    }

    private sealed class FakeBrowserRegistrationService : IBrowserRegistrationService
    {
        public List<BrowserRegistrationRequest> Requests { get; } = [];

        public Task<BrowserRegistrationResult> RegisterAsync(BrowserRegistrationRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(new BrowserRegistrationResult(true, "registered", request.TargetId, $"{request.TargetId}-password", true));
        }
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

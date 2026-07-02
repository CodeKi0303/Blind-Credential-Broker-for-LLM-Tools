using System.Text.Json;
using LlmPwManager.App;
using LlmPwManager.Config;
using LlmPwManager.Credentials;

namespace LlmPwManager.Tests;

public sealed class DoctorReportTests
{
    [Fact]
    public void DoctorReportsMissingCredentialsWithoutSecretValues()
    {
        var config = new AppConfig
        {
            DefaultClientProfile = "limited",
            ClientProfiles =
            [
                new() { Id = "limited", Permission = PermissionProfile.Limited }
            ],
            Credentials =
            [
                new() { Alias = "ssh-secret", Label = "SSH", UserName = "deploy" }
            ]
        };
        var report = DoctorReport.Build(
            config,
            new FakeCredentialStore(),
            "C:\\app\\config.json",
            "C:\\app\\audit.jsonl",
            Path.GetTempPath());

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var document = JsonDocument.Parse(json);

        Assert.Equal("warning", document.RootElement.GetProperty("status").GetString());
        Assert.Contains("\"alias\":\"ssh-secret\"", json);
        Assert.Contains("\"secret_visible_to_model\":false", json);
        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DoctorWarnsWhenLimitedProfileTargetsLackPolicies()
    {
        var config = new AppConfig
        {
            DefaultClientProfile = "limited",
            ClientProfiles =
            [
                new()
                {
                    Id = "limited",
                    Permission = PermissionProfile.Limited,
                    AllowedTools = ["ssh_run", "route_test", "db_query", "browser_login"]
                }
            ],
            Credentials =
            [
                new() { Alias = "ssh-secret", Label = "SSH", UserName = "deploy" },
                new() { Alias = "db-secret", Label = "DB", UserName = "readonly" },
                new() { Alias = "browser-secret", Label = "Browser", UserName = "operator@example.com" }
            ],
            SshTargets =
            [
                new()
                {
                    Id = "bastion",
                    Host = "bastion.example.com",
                    UserName = "deploy",
                    CredentialAlias = "ssh-secret"
                }
            ],
            Routes =
            [
                new() { Id = "bastion", SshChain = ["bastion"] }
            ],
            DbTargets =
            [
                new()
                {
                    Id = "payments",
                    Host = "10.0.0.10",
                    Port = 5432,
                    Database = "payments",
                    UserName = "readonly",
                    CredentialAlias = "db-secret",
                    MaxRows = 10
                }
            ],
            BrowserTargets =
            [
                new()
                {
                    Id = "admin-console",
                    LoginUrl = "https://admin.example.com/login",
                    UserName = "operator@example.com",
                    CredentialAlias = "browser-secret",
                    UserNameSelector = "#email",
                    PasswordSelector = "#password",
                    SubmitSelector = "button[type=submit]",
                    SuccessUrlContains = "/dashboard"
                }
            ]
        };

        var report = DoctorReport.Build(
            config,
            new FakeCredentialStore(),
            "C:\\app\\config.json",
            "C:\\app\\audit.jsonl",
            Path.GetTempPath());

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"name\":\"policy_coverage\"", json);
        Assert.Contains("\"status\":\"warning\"", json);
        Assert.Contains("\"ssh_run_missing_routes\":[\"bastion\"]", json);
        Assert.Contains("\"route_test_missing_routes\":[\"bastion\"]", json);
        Assert.Contains("\"db_query_missing_connections\":[\"payments\"]", json);
        Assert.Contains("\"browser_login_missing_targets\":[\"admin-console\"]", json);
    }

    [Fact]
    public void DoctorRedactsSecretLikeValuesFromConfigErrors()
    {
        var config = new AppConfig
        {
            DefaultClientProfile = "limited",
            ClientProfiles =
            [
                new() { Id = "limited", Permission = PermissionProfile.Limited }
            ],
            Credentials =
            [
                new() { Alias = "token=abc123", Label = "Accidental token", UserName = "deploy" }
            ],
            SshTargets =
            [
                new()
                {
                    Id = "bastion",
                    Host = "bastion.example.com",
                    UserName = "deploy",
                    CredentialAlias = "token=abc123"
                }
            ]
        };

        var report = DoctorReport.Build(
            config,
            new FakeCredentialStore(),
            "C:\\app\\config.json",
            "C:\\app\\audit.jsonl",
            Path.GetTempPath());

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("token=[REDACTED]", json);
        Assert.DoesNotContain("abc123", json);
    }

    private sealed class FakeCredentialStore : ICredentialStore
    {
        public bool Exists(string alias) => false;
        public string? GetSecret(string alias) => null;
        public void SaveSecret(string alias, string secret) { }
        public void DeleteSecret(string alias) { }
    }
}

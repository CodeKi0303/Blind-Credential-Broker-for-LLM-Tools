using System.Text.Json;
using LlmPwManager.Config;
using LlmPwManager.Credentials;

namespace LlmPwManager.Tests;

public sealed class ConfigSummaryTests
{
    [Fact]
    public void SummaryReportsCredentialStatusWithoutSecretValues()
    {
        var config = new AppConfig
        {
            DefaultClientProfile = "limited",
            ClientProfiles =
            [
                new() { Id = "limited", Permission = PermissionProfile.Limited, AllowedTools = ["ssh_run"] },
                new() { Id = "full", Permission = PermissionProfile.Full, AllowedTools = [] }
            ],
            Credentials =
            [
                new() { Alias = "prod-secret", Label = "Prod secret", UserName = "deploy" }
            ],
            SshTargets =
            [
                new()
                {
                    Id = "prod",
                    Host = "prod.example.com",
                    Port = 22,
                    UserName = "deploy",
                    CredentialAlias = "prod-secret"
                }
            ],
            Routes =
            [
                new() { Id = "prod", SshChain = ["prod"] }
            ]
        };
        var store = new FakeCredentialStore();
        store.SaveSecret("prod-secret", "super-secret-password");

        var summary = new ConfigSummary(config, store).Build("limited");
        var json = JsonSerializer.Serialize(summary, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"registered\":1", json);
        Assert.Contains("\"secret_visible_to_model\":false", json);
        Assert.DoesNotContain("super-secret-password", json);
    }

    [Fact]
    public void MinimalSummaryHidesOperationalDetailsFromNonFullProfiles()
    {
        var config = CreateDetailedConfig();
        var store = new FakeCredentialStore();
        store.SaveSecret("prod-secret", "super-secret-password");

        var summary = new ConfigSummary(config, store).Build("limited");
        var json = JsonSerializer.Serialize(summary, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"summary_scope\":\"minimal\"", json);
        Assert.Contains("\"id\":\"prod-route\"", json);
        Assert.Contains("\"id\":\"payments-db\"", json);
        Assert.Contains("\"id\":\"admin-console\"", json);
        Assert.DoesNotContain("prod.example.com", json);
        Assert.DoesNotContain("deploy", json);
        Assert.DoesNotContain("prod-secret", json);
        Assert.DoesNotContain("#password", json);
        Assert.DoesNotContain("systemctl status", json);
        Assert.DoesNotContain("ssh_chain", json);
        Assert.DoesNotContain("credential_alias", json);
        Assert.DoesNotContain("password_selector", json);
        Assert.DoesNotContain("command_prefixes", json);
    }

    [Fact]
    public void FullSummaryIncludesOperationalDetailsForManagementProfiles()
    {
        var config = CreateDetailedConfig();
        var store = new FakeCredentialStore();

        var summary = new ConfigSummary(config, store).Build("full");
        var json = JsonSerializer.Serialize(summary, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"summary_scope\":\"full\"", json);
        Assert.Contains("prod.example.com", json);
        Assert.Contains("prod-secret", json);
        Assert.Contains("#password", json);
        Assert.Contains("systemctl status", json);
        Assert.Contains("ssh_chain", json);
        Assert.Contains("credential_alias", json);
        Assert.Contains("password_selector", json);
        Assert.Contains("command_prefixes", json);
    }

    private static AppConfig CreateDetailedConfig() => new()
    {
        DefaultClientProfile = "limited",
        ClientProfiles =
        [
            new() { Id = "limited", Permission = PermissionProfile.Limited, AllowedTools = ["config_summary", "ssh_run", "db_query", "browser_login"] },
            new() { Id = "full", Permission = PermissionProfile.Full, AllowedTools = [] }
        ],
        Credentials =
        [
            new() { Alias = "prod-secret", Label = "Prod secret", UserName = "deploy" }
        ],
        SshTargets =
        [
            new()
            {
                Id = "prod",
                Host = "prod.example.com",
                Port = 22,
                UserName = "deploy",
                CredentialAlias = "prod-secret"
            }
        ],
        Routes =
        [
            new() { Id = "prod-route", SshChain = ["prod"] }
        ],
        DbTargets =
        [
            new()
            {
                Id = "payments-db",
                Engine = DbEngine.Postgres,
                Host = "db.internal",
                Port = 5432,
                Database = "payments",
                UserName = "dbuser",
                CredentialAlias = "prod-secret",
                RouteId = "prod-route"
            }
        ],
        BrowserTargets =
        [
            new()
            {
                Id = "admin-console",
                LoginUrl = "https://admin.example.com/login",
                UserName = "operator@example.com",
                CredentialAlias = "prod-secret",
                UserNameSelector = "#email",
                PasswordSelector = "#password",
                SubmitSelector = "button[type=submit]",
                SuccessUrlContains = "/dashboard"
            }
        ],
        Policies =
        [
            new()
            {
                Id = "safe-ssh",
                Tools = ["ssh_run"],
                RouteIds = ["prod-route"],
                CommandPrefixes = ["systemctl status"],
                MinPermission = PermissionProfile.Limited
            }
        ]
    };

    private sealed class FakeCredentialStore : ICredentialStore
    {
        private readonly Dictionary<string, string> secrets = new(StringComparer.OrdinalIgnoreCase);

        public bool Exists(string alias) => secrets.ContainsKey(alias);
        public string? GetSecret(string alias) => secrets.GetValueOrDefault(alias);
        public void SaveSecret(string alias, string secret) => secrets[alias] = secret;
        public void DeleteSecret(string alias) => secrets.Remove(alias);
    }
}

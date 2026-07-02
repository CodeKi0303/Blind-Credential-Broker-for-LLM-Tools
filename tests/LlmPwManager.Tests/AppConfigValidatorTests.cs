using LlmPwManager.Config;

namespace LlmPwManager.Tests;

public sealed class AppConfigValidatorTests
{
    [Fact]
    public void ValidPasswordSshAndDbConfigHasNoErrors()
    {
        var errors = AppConfigValidator.Validate(CreateValidConfig());

        Assert.Empty(errors);
    }

    [Fact]
    public void RouteReferencingMissingSshTargetIsInvalid()
    {
        var config = CreateValidConfig();
        config.Routes[0].SshChain = ["missing"];

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("unknown sshTarget 'missing'"));
    }

    [Fact]
    public void DbTargetReferencingMissingCredentialIsInvalid()
    {
        var config = CreateValidConfig();
        config.DbTargets[0].CredentialAlias = "missing-db-secret";

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("unknown credential 'missing-db-secret'"));
    }

    [Fact]
    public void SessionIdleTimeoutMustBePositive()
    {
        var config = CreateValidConfig();
        config.SessionIdleTimeoutMinutes = 0;

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("sessionIdleTimeoutMinutes"));
    }

    [Fact]
    public void ClientProfileReferencingUnknownToolIsInvalid()
    {
        var config = CreateValidConfig();
        config.ClientProfiles[0].AllowedTools.Add("ssh_rnu");

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("clientProfile 'limited' allowedTools references unknown tool 'ssh_rnu'"));
    }

    [Fact]
    public void InvalidConfiguredIdentifierIsRejected()
    {
        var config = CreateValidConfig();
        config.Credentials[0].Alias = "ssh secret";

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("credentials id 'ssh secret' is invalid"));
        Assert.Contains(errors, e => e.Contains("unknown credential 'ssh-secret'"));
    }

    [Fact]
    public void DuplicatePolicyIdIsInvalid()
    {
        var config = CreateValidConfig();
        config.Policies.Add(new PolicyRule { Id = "read-ssh", Tools = ["ssh_run"], RouteIds = ["bastion"] });
        config.Policies.Add(new PolicyRule { Id = "read-ssh", Tools = ["route_test"], RouteIds = ["bastion"] });

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("policies contains duplicate id 'read-ssh'"));
    }

    [Fact]
    public void PolicyReferencingUnknownToolIsInvalid()
    {
        var config = CreateValidConfig();
        config.Policies.Add(new PolicyRule { Id = "bad-tool", Tools = ["db_queri"], ConnectionIds = ["db"] });

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("policy 'bad-tool' tools references unknown tool 'db_queri'"));
    }

    [Fact]
    public void NonFullSshPolicyWithoutCommandPrefixesIsInvalid()
    {
        var config = CreateValidConfig();
        config.Policies.Add(new PolicyRule
        {
            Id = "too-broad-ssh",
            Tools = ["ssh_run"],
            RouteIds = ["bastion"],
            MinPermission = PermissionProfile.Limited
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("policy 'too-broad-ssh' allows ssh_run for non-full profiles and must define commandPrefixes"));
    }

    [Fact]
    public void FullOnlySshPolicyWithoutCommandPrefixesIsValid()
    {
        var config = CreateValidConfig();
        config.Policies.Add(new PolicyRule
        {
            Id = "full-ssh",
            Tools = ["ssh_run"],
            RouteIds = ["bastion"],
            MinPermission = PermissionProfile.Full
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.DoesNotContain(errors, e => e.Contains("policy 'full-ssh' allows ssh_run"));
    }

    [Fact]
    public void PrivateKeySshWithoutPassphraseCredentialIsValid()
    {
        var config = CreateValidConfig();
        config.SshTargets.Add(new SshTarget
        {
            Id = "key-host",
            Host = "key.example.com",
            Port = 22,
            UserName = "deploy",
            AuthMode = SshAuthMode.PrivateKey,
            PrivateKeyPath = "%USERPROFILE%\\.ssh\\id_ed25519"
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
    }

    [Fact]
    public void PrivateKeySshWithMissingPassphraseCredentialIsInvalid()
    {
        var config = CreateValidConfig();
        config.SshTargets.Add(new SshTarget
        {
            Id = "key-host",
            Host = "key.example.com",
            Port = 22,
            UserName = "deploy",
            AuthMode = SshAuthMode.PrivateKey,
            PrivateKeyPath = "%USERPROFILE%\\.ssh\\id_ed25519",
            CredentialAlias = "missing-passphrase"
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("unknown credential 'missing-passphrase'"));
    }

    [Fact]
    public void DisabledBrowserTargetDoesNotRequireCredential()
    {
        var config = CreateValidConfig();
        config.BrowserTargets.Add(new BrowserTarget
        {
            Id = "future-browser",
            LoginUrl = "https://example.com/login",
            CredentialAlias = "not-yet-created",
            IsolationMode = BrowserIsolationMode.Disabled
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
    }

    [Fact]
    public void ManagedBrowserTargetRequiresSelectorsAndSuccessCondition()
    {
        var config = CreateValidConfig();
        config.Credentials.Add(new CredentialRef { Alias = "browser-secret", Label = "Browser", UserName = "user@example.com" });
        config.BrowserTargets.Add(new BrowserTarget
        {
            Id = "admin",
            LoginUrl = "https://example.com/login",
            UserName = "user@example.com",
            CredentialAlias = "browser-secret",
            IsolationMode = BrowserIsolationMode.ManagedProfile,
            UserNameSelector = "#email",
            PasswordSelector = "#password",
            SubmitSelector = "button[type=submit]"
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("successSelector or successUrlContains"));
    }

    [Fact]
    public void ManagedBrowserTargetWithSuccessUrlIsValid()
    {
        var config = CreateValidConfig();
        config.Credentials.Add(new CredentialRef { Alias = "browser-secret", Label = "Browser", UserName = "user@example.com" });
        config.BrowserTargets.Add(new BrowserTarget
        {
            Id = "admin",
            LoginUrl = "https://example.com/login",
            UserName = "user@example.com",
            CredentialAlias = "browser-secret",
            IsolationMode = BrowserIsolationMode.ManagedProfile,
            UserNameSelector = "#email",
            PasswordSelector = "#password",
            SubmitSelector = "button[type=submit]",
            SuccessUrlContains = "/dashboard"
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
    }

    [Fact]
    public void PolicyReferencingMissingBrowserTargetIsInvalid()
    {
        var config = CreateValidConfig();
        config.Policies.Add(new PolicyRule
        {
            Id = "bad-browser-policy",
            Tools = ["browser_login"],
            BrowserTargetIds = ["missing-browser"]
        });

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, e => e.Contains("unknown browserTarget 'missing-browser'"));
    }

    private static AppConfig CreateValidConfig() => new()
    {
        DefaultClientProfile = "limited",
        ClientProfiles =
        [
            new() { Id = "limited", Permission = PermissionProfile.Limited, AllowedTools = ["ssh_run", "db_query"] }
        ],
        Credentials =
        [
            new() { Alias = "ssh-secret", Label = "SSH", UserName = "deploy" },
            new() { Alias = "db-secret", Label = "DB", UserName = "readonly" }
        ],
        SshTargets =
        [
            new()
            {
                Id = "bastion",
                Host = "bastion.example.com",
                Port = 22,
                UserName = "deploy",
                AuthMode = SshAuthMode.Password,
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
                Id = "db",
                Engine = DbEngine.Postgres,
                Host = "10.0.0.10",
                Port = 5432,
                Database = "app",
                UserName = "readonly",
                CredentialAlias = "db-secret",
                RouteId = "bastion",
                MaxRows = 10
            }
        ]
    };
}

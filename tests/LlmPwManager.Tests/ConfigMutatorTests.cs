using LlmPwManager.Config;
using LlmPwManager.Policy;

namespace LlmPwManager.Tests;

public sealed class ConfigMutatorTests
{
    [Fact]
    public void CanBuildMinimalSshRouteConfigWithoutSecrets()
    {
        var config = BaseConfig();

        ConfigMutator.AddCredential(config, "prod-deploy", "deploy", "Prod deploy");
        ConfigMutator.AddSshTarget(
            config,
            "prod",
            "prod.example.com",
            22,
            "deploy",
            SshAuthMode.Password,
            "prod-deploy",
            null);
        ConfigMutator.AddRoute(config, "prod-route", ["prod"]);

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
        Assert.Single(config.Credentials);
        Assert.Single(config.SshTargets);
        Assert.Single(config.Routes);
    }

    [Fact]
    public void DuplicateCredentialAliasIsRejected()
    {
        var config = BaseConfig();
        ConfigMutator.AddCredential(config, "prod-deploy", "deploy", "Prod deploy");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ConfigMutator.AddCredential(config, "prod-deploy", "deploy", "Duplicate"));

        Assert.Contains("already exists", ex.Message);
    }

    [Fact]
    public void CredentialAliasWithUnsafeCharactersIsRejected()
    {
        var config = BaseConfig();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ConfigMutator.AddCredential(config, "prod deploy\nsecret", "deploy", "Prod deploy"));

        Assert.Contains("credential alias 'prod deploy", ex.Message);
        Assert.Contains("letters, numbers, dot, underscore, or dash", ex.Message);
    }

    [Fact]
    public void CanAddClientProfileAndSetDefault()
    {
        var config = BaseConfig();

        ConfigMutator.AddClientProfile(
            config,
            "claude-desktop",
            PermissionProfile.Approval,
            ["ssh_run", "credential_status", "config_summary"]);
        ConfigMutator.SetDefaultProfile(config, "claude-desktop");

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
        Assert.Equal("claude-desktop", config.DefaultClientProfile);
        Assert.Contains(config.ClientProfiles, profile => profile.Id == "claude-desktop" && profile.Permission == PermissionProfile.Approval);
    }

    [Fact]
    public void DefaultProfileMustExist()
    {
        var config = BaseConfig();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ConfigMutator.SetDefaultProfile(config, "missing"));

        Assert.Contains("does not exist", ex.Message);
    }

    [Fact]
    public void CanSetSessionIdleTimeout()
    {
        var config = BaseConfig();

        ConfigMutator.SetSessionIdleTimeout(config, 10);

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
        Assert.Equal(10, config.SessionIdleTimeoutMinutes);
    }

    [Fact]
    public void SessionIdleTimeoutMustBeAtLeastOneMinute()
    {
        var config = BaseConfig();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ConfigMutator.SetSessionIdleTimeout(config, 0));

        Assert.Contains("at least 1 minute", ex.Message);
    }

    [Fact]
    public void PasswordSshTargetMustReferenceCredential()
    {
        var config = BaseConfig();

        ConfigMutator.AddSshTarget(
            config,
            "prod",
            "prod.example.com",
            22,
            "deploy",
            SshAuthMode.Password,
            "missing",
            null);

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, error => error.Contains("unknown credential 'missing'"));
    }

    [Fact]
    public void CanBuildDbTargetThroughRoute()
    {
        var config = BaseConfig();
        ConfigMutator.AddCredential(config, "ssh-secret", "deploy", "SSH");
        ConfigMutator.AddCredential(config, "db-secret", "readonly", "DB");
        ConfigMutator.AddSshTarget(config, "bastion", "bastion.example.com", 22, "deploy", SshAuthMode.Password, "ssh-secret", null);
        ConfigMutator.AddRoute(config, "bastion", ["bastion"]);

        ConfigMutator.AddDbTarget(
            config,
            "payments",
            DbEngine.Postgres,
            "10.0.0.10",
            5432,
            "payments",
            "readonly",
            "db-secret",
            "bastion",
            25);

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
        Assert.Single(config.DbTargets);
        Assert.Equal("bastion", config.DbTargets[0].RouteId);
    }

    [Fact]
    public void PrivateKeySshTargetCanOmitPassphraseCredential()
    {
        var config = BaseConfig();

        ConfigMutator.AddSshTarget(
            config,
            "key-host",
            "key.example.com",
            22,
            "deploy",
            SshAuthMode.PrivateKey,
            "",
            "%USERPROFILE%\\.ssh\\id_ed25519");

        var errors = AppConfigValidator.Validate(config);

        Assert.Empty(errors);
    }

    [Fact]
    public void CanAddSshPolicyThatAllowsLimitedReadCommand()
    {
        var config = BaseConfig();
        ConfigMutator.AddCredential(config, "ssh-secret", "deploy", "SSH");
        ConfigMutator.AddSshTarget(config, "bastion", "bastion.example.com", 22, "deploy", SshAuthMode.Password, "ssh-secret", null);
        ConfigMutator.AddRoute(config, "bastion", ["bastion"]);

        ConfigMutator.AddSshPolicy(
            config,
            "read-bastion",
            ["bastion"],
            ["df ", "uptime"],
            allowShellOperators: false,
            PermissionProfile.Limited);

        var errors = AppConfigValidator.Validate(config);
        var decision = new PolicyEvaluator(config).Evaluate(new ToolRequest(
            "ssh_run",
            "limited",
            RouteId: "bastion",
            Command: "uptime"));

        Assert.Empty(errors);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void CanAddDbPolicyThatAllowsLimitedReadQuery()
    {
        var config = BaseConfig();
        ConfigMutator.AddCredential(config, "db-secret", "readonly", "DB");
        ConfigMutator.AddDbTarget(config, "payments", DbEngine.Postgres, "10.0.0.10", 5432, "payments", "readonly", "db-secret", null, 50);

        ConfigMutator.AddDbPolicy(
            config,
            "read-payments",
            ["payments"],
            allowWriteSql: false,
            PermissionProfile.Limited);

        var errors = AppConfigValidator.Validate(config);
        var decision = new PolicyEvaluator(config).Evaluate(new ToolRequest(
            "db_query",
            "limited",
            ConnectionId: "payments",
            Sql: "select count(*) from payment_logs"));

        Assert.Empty(errors);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void CanAddBrowserPolicyThatAllowsLimitedLogin()
    {
        var config = BaseConfig();
        ConfigMutator.AddCredential(config, "browser-secret", "operator@example.com", "Browser");
        ConfigMutator.AddBrowserTarget(
            config,
            "admin-console",
            "https://admin.example.com/login",
            "operator@example.com",
            "browser-secret",
            BrowserIsolationMode.ManagedProfile,
            "#email",
            "#password",
            "button[type=submit]",
            null,
            "/dashboard",
            ".login-error",
            30);

        ConfigMutator.AddBrowserPolicy(
            config,
            "login-admin",
            ["admin-console"],
            PermissionProfile.Limited);

        var errors = AppConfigValidator.Validate(config);
        var decision = new PolicyEvaluator(config).Evaluate(new ToolRequest(
            "browser_login",
            "limited",
            BrowserTargetId: "admin-console"));

        Assert.Empty(errors);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void PolicyReferencingMissingRouteIsRejectedByValidation()
    {
        var config = BaseConfig();

        ConfigMutator.AddSshPolicy(config, "bad", ["missing"], ["df"], false, PermissionProfile.Limited);

        var errors = AppConfigValidator.Validate(config);

        Assert.Contains(errors, error => error.Contains("unknown route 'missing'"));
    }

    private static AppConfig BaseConfig() => new()
    {
        DefaultClientProfile = "limited",
        ClientProfiles =
        [
            new()
            {
                Id = "limited",
                Permission = PermissionProfile.Limited,
                AllowedTools = ["ssh_run", "route_test", "db_query", "browser_login", "credential_status", "forget_credential", "config_summary", "audit_tail"]
            }
        ]
    };
}

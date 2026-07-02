using System.Text.Json.Serialization;

namespace LlmPwManager.Config;

internal sealed class AppConfig
{
    public string DefaultClientProfile { get; set; } = "limited";
    public int SessionIdleTimeoutMinutes { get; set; } = 30;
    public List<ClientProfile> ClientProfiles { get; set; } = [];
    public List<CredentialRef> Credentials { get; set; } = [];
    public List<SshTarget> SshTargets { get; set; } = [];
    public List<RouteDefinition> Routes { get; set; } = [];
    public List<DbTarget> DbTargets { get; set; } = [];
    public List<BrowserTarget> BrowserTargets { get; set; } = [];
    public List<PolicyRule> Policies { get; set; } = [];
}

internal sealed class ClientProfile
{
    public string Id { get; set; } = "";
    public PermissionProfile Permission { get; set; } = PermissionProfile.Limited;
    public List<string> AllowedTools { get; set; } = [];
}

internal enum PermissionProfile
{
    Full,
    Limited,
    Approval,
    DenyByDefault
}

internal sealed class CredentialRef
{
    public string Alias { get; set; } = "";
    public string Label { get; set; } = "";
    public string UserName { get; set; } = "";
}

internal sealed class SshTarget
{
    public string Id { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 22;
    public string UserName { get; set; } = "";
    public SshAuthMode AuthMode { get; set; } = SshAuthMode.Password;
    public string CredentialAlias { get; set; } = "";
    public string? PrivateKeyPath { get; set; }
}

internal enum SshAuthMode
{
    Password,
    PrivateKey
}

internal sealed class RouteDefinition
{
    public string Id { get; set; } = "";
    public List<string> SshChain { get; set; } = [];
}

internal sealed class DbTarget
{
    public string Id { get; set; } = "";
    public DbEngine Engine { get; set; } = DbEngine.Postgres;
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string Database { get; set; } = "";
    public string UserName { get; set; } = "";
    public string CredentialAlias { get; set; } = "";
    public string? RouteId { get; set; }
    public int MaxRows { get; set; } = 100;
}

internal sealed class BrowserTarget
{
    public string Id { get; set; } = "";
    public string LoginUrl { get; set; } = "";
    public string UserName { get; set; } = "";
    public string CredentialAlias { get; set; } = "";
    public BrowserIsolationMode IsolationMode { get; set; } = BrowserIsolationMode.ManagedProfile;
    public string UserNameSelector { get; set; } = "";
    public string PasswordSelector { get; set; } = "";
    public string SubmitSelector { get; set; } = "";
    public string? SuccessSelector { get; set; }
    public string? SuccessUrlContains { get; set; }
    public string? FailureSelector { get; set; }
    public int LoginTimeoutSeconds { get; set; } = 30;
}

internal enum BrowserIsolationMode
{
    ManagedProfile,
    ExtensionNativeMessaging,
    Disabled
}

[JsonConverter(typeof(JsonStringEnumConverter<DbEngine>))]
internal enum DbEngine
{
    Postgres,
    MySql
}

internal sealed class PolicyRule
{
    public string Id { get; set; } = "";
    public List<string> Tools { get; set; } = [];
    public List<string> RouteIds { get; set; } = [];
    public List<string> ConnectionIds { get; set; } = [];
    public List<string> BrowserTargetIds { get; set; } = [];
    public List<string> CommandPrefixes { get; set; } = [];
    public bool AllowShellOperators { get; set; }
    public bool AllowWriteSql { get; set; }
    public PermissionProfile MinPermission { get; set; } = PermissionProfile.Limited;
}

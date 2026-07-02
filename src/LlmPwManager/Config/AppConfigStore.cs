using System.Text.Json;
using System.Text.Json.Serialization;

namespace LlmPwManager.Config;

internal static class AppConfigStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    static AppConfigStore()
    {
        Options.Converters.Add(new JsonStringEnumConverter());
    }

    public static AppConfig LoadOrCreate(string path)
    {
        if (!File.Exists(path))
        {
            var config = CreateSample();
            File.WriteAllText(path, JsonSerializer.Serialize(config, Options));
            return config;
        }

        var text = File.ReadAllText(path);
        return JsonSerializer.Deserialize<AppConfig>(text, Options) ?? new AppConfig();
    }

    public static void WriteSample(string path, bool overwrite)
    {
        if (File.Exists(path) && !overwrite)
        {
            throw new InvalidOperationException($"Config already exists: {path}. Use --force to overwrite.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(CreateSample(), Options));
    }

    public static void Save(string path, AppConfig config)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(config, Options));
    }

    private static AppConfig CreateSample() => new()
    {
        DefaultClientProfile = "limited",
        ClientProfiles =
        [
            new() { Id = "full", Permission = PermissionProfile.Full, AllowedTools = ["ssh_run", "ssh_register", "ssh_open_session", "session_list", "session_close", "db_query", "browser_login", "route_test", "policy_check", "credential_status", "forget_credential", "config_summary", "audit_tail"] },
            new() { Id = "limited", Permission = PermissionProfile.Limited, AllowedTools = ["ssh_run", "ssh_register", "ssh_open_session", "session_list", "session_close", "db_query", "browser_login", "route_test", "policy_check", "credential_status", "forget_credential", "config_summary", "audit_tail"] }
        ],
        Credentials =
        [
            new() { Alias = "bastion-deploy", Label = "Bastion deploy password", UserName = "deploy" },
            new() { Alias = "app-deploy", Label = "Internal app deploy password", UserName = "deploy" },
            new() { Alias = "payments-db-readonly", Label = "Payments DB readonly password", UserName = "readonly" },
            new() { Alias = "admin-console-password", Label = "Admin console password", UserName = "operator@example.com" }
        ],
        SshTargets =
        [
            new() { Id = "bastion", Host = "bastion.example.com", Port = 22, UserName = "deploy", AuthMode = SshAuthMode.Password, CredentialAlias = "bastion-deploy" },
            new() { Id = "app-02", Host = "10.20.0.12", Port = 22, UserName = "deploy", AuthMode = SshAuthMode.Password, CredentialAlias = "app-deploy" }
        ],
        Routes =
        [
            new() { Id = "bastion", SshChain = ["bastion"] },
            new() { Id = "bastion-to-app-02", SshChain = ["bastion", "app-02"] }
        ],
        DbTargets =
        [
            new()
            {
                Id = "payments-db-via-bastion",
                Engine = DbEngine.Postgres,
                Host = "10.30.0.20",
                Port = 5432,
                Database = "payments",
                UserName = "readonly",
                CredentialAlias = "payments-db-readonly",
                RouteId = "bastion",
                MaxRows = 50
            }
        ],
        BrowserTargets =
        [
            new()
            {
                Id = "admin-console",
                LoginUrl = "https://admin.example.com/login",
                UserName = "operator@example.com",
                CredentialAlias = "admin-console-password",
                IsolationMode = BrowserIsolationMode.Disabled
            }
        ],
        Policies =
        [
            new()
            {
                Id = "read-ssh",
                Tools = ["ssh_run", "route_test"],
                RouteIds = ["bastion", "bastion-to-app-02"],
                CommandPrefixes = ["df ", "df", "systemctl status", "uptime", "whoami", "hostname"],
                MinPermission = PermissionProfile.Limited
            },
            new()
            {
                Id = "read-db",
                Tools = ["db_query"],
                ConnectionIds = ["payments-db-via-bastion"],
                AllowWriteSql = false,
                MinPermission = PermissionProfile.Limited
            },
            new()
            {
                Id = "login-browser",
                Tools = ["browser_login"],
                BrowserTargetIds = ["admin-console"],
                MinPermission = PermissionProfile.Limited
            }
        ]
    };
}

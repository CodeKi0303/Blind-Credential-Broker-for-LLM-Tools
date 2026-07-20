using System.Text.Json;
using System.Text.Json.Serialization;
using LlmPwManager.IO;

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
        using var fileLock = CrossProcessFileLock.Acquire(path);
        return LoadOrCreateUnlocked(path);
    }

    public static void WriteSample(string path, bool overwrite)
    {
        using var fileLock = CrossProcessFileLock.Acquire(path);
        if (File.Exists(path) && !overwrite)
        {
            throw new InvalidOperationException($"Config already exists: {path}. Use --force to overwrite.");
        }

        WriteAtomicUnlocked(path, CreateSample());
    }

    public static void Save(string path, AppConfig config)
    {
        using var fileLock = CrossProcessFileLock.Acquire(path);
        WriteAtomicUnlocked(path, config);
    }

    public static AppConfig Update(string path, Action<AppConfig> update)
    {
        using var fileLock = CrossProcessFileLock.Acquire(path);
        var config = LoadOrCreateUnlocked(path);
        update(config);
        WriteAtomicUnlocked(path, config);
        return config;
    }

    public static void CopyInto(AppConfig destination, AppConfig source)
    {
        destination.DefaultClientProfile = source.DefaultClientProfile;
        destination.SessionIdleTimeoutMinutes = source.SessionIdleTimeoutMinutes;
        destination.ClientProfiles = source.ClientProfiles;
        destination.Credentials = source.Credentials;
        destination.SshTargets = source.SshTargets;
        destination.Routes = source.Routes;
        destination.DbTargets = source.DbTargets;
        destination.BrowserTargets = source.BrowserTargets;
        destination.Policies = source.Policies;
    }

    private static AppConfig LoadOrCreateUnlocked(string path)
    {
        if (!File.Exists(path))
        {
            var sample = CreateSample();
            WriteAtomicUnlocked(path, sample);
            return sample;
        }

        var text = File.ReadAllText(path);
        var config = JsonSerializer.Deserialize<AppConfig>(text, Options) ?? new AppConfig();
        if (ApplyMigrations(config))
        {
            WriteAtomicUnlocked(path, config);
        }

        return config;
    }

    private static bool ApplyMigrations(AppConfig config)
    {
        var changed = false;
        foreach (var profile in config.ClientProfiles)
        {
            if (profile.Id.Equals("full", StringComparison.OrdinalIgnoreCase) ||
                profile.Id.Equals("limited", StringComparison.OrdinalIgnoreCase))
            {
                changed |= AddMissingTools(profile, DefaultMcpTools);
            }
        }

        return changed;
    }

    private static bool AddMissingTools(ClientProfile profile, IReadOnlyList<string> tools)
    {
        var changed = false;
        foreach (var tool in tools)
        {
            if (profile.AllowedTools.Contains(tool, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            profile.AllowedTools.Add(tool);
            changed = true;
        }

        return changed;
    }

    private static void WriteAtomicUnlocked(string path, AppConfig config)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(tempPath, JsonSerializer.Serialize(config, Options));
            File.Move(tempPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    private static AppConfig CreateSample() => new()
    {
        DefaultClientProfile = "limited",
        ClientProfiles =
        [
            new() { Id = "full", Permission = PermissionProfile.Full, AllowedTools = [.. DefaultMcpTools] },
            new() { Id = "limited", Permission = PermissionProfile.Limited, AllowedTools = [.. DefaultMcpTools] }
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
                Id = "read-sudo-ssh",
                Tools = ["ssh_sudo_run"],
                RouteIds = ["bastion", "bastion-to-app-02"],
                CommandPrefixes = ["whoami", "id", "hostname", "systemctl status", "journalctl", "cat ", "head ", "tail ", "ls "],
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

    private static readonly string[] DefaultMcpTools =
    [
        "ssh_run",
        "ssh_sudo_run",
        "ssh_register",
        "ssh_open_session",
        "session_list",
        "session_close",
        "db_query",
        "db_register",
        "browser_login",
        "browser_register",
        "route_test",
        "policy_check",
        "credential_status",
        "forget_credential",
        "config_summary",
        "audit_tail"
    ];
}

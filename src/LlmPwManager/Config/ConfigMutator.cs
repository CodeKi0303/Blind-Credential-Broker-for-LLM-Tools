namespace LlmPwManager.Config;

internal static class ConfigMutator
{
    public static void AddClientProfile(
        AppConfig config,
        string id,
        PermissionProfile permission,
        IReadOnlyList<string> allowedTools)
    {
        RequireId(id, "client profile id");
        EnsureMissing(config.ClientProfiles.Select(profile => profile.Id), id, "client profile");
        config.ClientProfiles.Add(new ClientProfile
        {
            Id = id,
            Permission = permission,
            AllowedTools = NormalizeList(allowedTools)
        });
    }

    public static void SetDefaultProfile(AppConfig config, string id)
    {
        RequireId(id, "client profile id");
        if (!config.ClientProfiles.Any(profile => profile.Id.Equals(id, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"client profile '{id}' does not exist.");
        }

        config.DefaultClientProfile = id;
    }

    public static void SetSessionIdleTimeout(AppConfig config, int minutes)
    {
        if (minutes < 1)
        {
            throw new InvalidOperationException("session idle timeout must be at least 1 minute.");
        }

        config.SessionIdleTimeoutMinutes = minutes;
    }

    public static void AddCredential(AppConfig config, string alias, string userName, string label)
    {
        RequireId(alias, "credential alias");
        EnsureMissing(config.Credentials.Select(c => c.Alias), alias, "credential");
        config.Credentials.Add(new CredentialRef
        {
            Alias = alias,
            UserName = userName,
            Label = string.IsNullOrWhiteSpace(label) ? alias : label
        });
    }

    public static void AddSshTarget(
        AppConfig config,
        string id,
        string host,
        int port,
        string userName,
        SshAuthMode authMode,
        string credentialAlias,
        string? privateKeyPath)
    {
        RequireId(id, "ssh target id");
        EnsureMissing(config.SshTargets.Select(t => t.Id), id, "ssh target");
        config.SshTargets.Add(new SshTarget
        {
            Id = id,
            Host = host,
            Port = port,
            UserName = userName,
            AuthMode = authMode,
            CredentialAlias = credentialAlias,
            PrivateKeyPath = privateKeyPath
        });
    }

    public static void AddRoute(AppConfig config, string id, IReadOnlyList<string> sshChain)
    {
        RequireId(id, "route id");
        EnsureMissing(config.Routes.Select(r => r.Id), id, "route");
        config.Routes.Add(new RouteDefinition
        {
            Id = id,
            SshChain = sshChain.Where(item => !string.IsNullOrWhiteSpace(item)).Select(item => item.Trim()).ToList()
        });
    }

    public static void AddDbTarget(
        AppConfig config,
        string id,
        DbEngine engine,
        string host,
        int port,
        string database,
        string userName,
        string credentialAlias,
        string? routeId,
        int maxRows)
    {
        RequireId(id, "db target id");
        EnsureMissing(config.DbTargets.Select(db => db.Id), id, "db target");
        config.DbTargets.Add(new DbTarget
        {
            Id = id,
            Engine = engine,
            Host = host,
            Port = port,
            Database = database,
            UserName = userName,
            CredentialAlias = credentialAlias,
            RouteId = string.IsNullOrWhiteSpace(routeId) ? null : routeId,
            MaxRows = maxRows
        });
    }

    public static void AddSshPolicy(
        AppConfig config,
        string id,
        IReadOnlyList<string> routeIds,
        IReadOnlyList<string> commandPrefixes,
        bool allowShellOperators,
        PermissionProfile minPermission)
    {
        RequireId(id, "policy id");
        EnsureMissing(config.Policies.Select(policy => policy.Id), id, "policy");
        config.Policies.Add(new PolicyRule
        {
            Id = id,
            Tools = ["ssh_run", "route_test"],
            RouteIds = NormalizeList(routeIds),
            CommandPrefixes = NormalizeList(commandPrefixes),
            AllowShellOperators = allowShellOperators,
            MinPermission = minPermission
        });
    }

    public static void AddDbPolicy(
        AppConfig config,
        string id,
        IReadOnlyList<string> connectionIds,
        bool allowWriteSql,
        PermissionProfile minPermission)
    {
        RequireId(id, "policy id");
        EnsureMissing(config.Policies.Select(policy => policy.Id), id, "policy");
        config.Policies.Add(new PolicyRule
        {
            Id = id,
            Tools = ["db_query"],
            ConnectionIds = NormalizeList(connectionIds),
            AllowWriteSql = allowWriteSql,
            MinPermission = minPermission
        });
    }

    public static void AddBrowserPolicy(
        AppConfig config,
        string id,
        IReadOnlyList<string> browserTargetIds,
        PermissionProfile minPermission)
    {
        RequireId(id, "policy id");
        EnsureMissing(config.Policies.Select(policy => policy.Id), id, "policy");
        config.Policies.Add(new PolicyRule
        {
            Id = id,
            Tools = ["browser_login"],
            BrowserTargetIds = NormalizeList(browserTargetIds),
            MinPermission = minPermission
        });
    }

    public static void AddBrowserTarget(
        AppConfig config,
        string id,
        string loginUrl,
        string userName,
        string credentialAlias,
        BrowserIsolationMode isolationMode,
        string userNameSelector,
        string passwordSelector,
        string submitSelector,
        string? successSelector,
        string? successUrlContains,
        string? failureSelector,
        int loginTimeoutSeconds)
    {
        RequireId(id, "browser target id");
        EnsureMissing(config.BrowserTargets.Select(browser => browser.Id), id, "browser target");
        config.BrowserTargets.Add(new BrowserTarget
        {
            Id = id,
            LoginUrl = loginUrl,
            UserName = userName,
            CredentialAlias = credentialAlias,
            IsolationMode = isolationMode,
            UserNameSelector = userNameSelector,
            PasswordSelector = passwordSelector,
            SubmitSelector = submitSelector,
            SuccessSelector = successSelector,
            SuccessUrlContains = successUrlContains,
            FailureSelector = failureSelector,
            LoginTimeoutSeconds = loginTimeoutSeconds
        });
    }

    private static List<string> NormalizeList(IReadOnlyList<string> values)
    {
        return values.Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .ToList();
    }

    private static void RequireId(string id, string label)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            throw new InvalidOperationException($"{label} cannot be empty.");
        }

        if (!ConfigIdentifier.IsValid(id))
        {
            throw new InvalidOperationException(ConfigIdentifier.Error(label, id));
        }
    }

    private static void EnsureMissing(IEnumerable<string> existingIds, string id, string label)
    {
        if (existingIds.Any(existing => existing.Equals(id, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"{label} '{id}' already exists.");
        }
    }
}

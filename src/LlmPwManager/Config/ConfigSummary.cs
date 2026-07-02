using LlmPwManager.Credentials;

namespace LlmPwManager.Config;

internal sealed class ConfigSummary(AppConfig config, ICredentialStore credentials)
{
    public object Build(string clientProfile)
    {
        var profile = config.ClientProfiles.FirstOrDefault(profile =>
            profile.Id.Equals(clientProfile, StringComparison.OrdinalIgnoreCase));

        return profile?.Permission == PermissionProfile.Full
            ? BuildFull(clientProfile, profile)
            : BuildMinimal(clientProfile, profile);
    }

    private object BuildFull(string clientProfile, ClientProfile? profile)
    {
        return new
        {
            client_profile = clientProfile,
            permission = profile?.Permission.ToString() ?? "Unknown",
            summary_scope = "full",
            default_client_profile = config.DefaultClientProfile,
            session_idle_timeout_minutes = config.SessionIdleTimeoutMinutes,
            client_profiles = config.ClientProfiles.Select(profile => new
            {
                id = profile.Id,
                permission = profile.Permission.ToString(),
                allowed_tools = profile.AllowedTools
            }),
            credentials = config.Credentials.Select(credential => new
            {
                alias = credential.Alias,
                label = credential.Label,
                user_name = credential.UserName,
                status = credentials.Exists(credential.Alias) ? "registered" : "missing",
                secret_visible_to_model = false
            }),
            ssh_targets = config.SshTargets.Select(target => new
            {
                id = target.Id,
                host = target.Host,
                port = target.Port,
                user_name = target.UserName,
                auth_mode = target.AuthMode.ToString(),
                credential_alias = string.IsNullOrWhiteSpace(target.CredentialAlias) ? null : target.CredentialAlias,
                has_private_key_path = !string.IsNullOrWhiteSpace(target.PrivateKeyPath)
            }),
            routes = config.Routes.Select(route => new
            {
                id = route.Id,
                ssh_chain = route.SshChain
            }),
            db_targets = config.DbTargets.Select(db => new
            {
                id = db.Id,
                engine = db.Engine.ToString(),
                host = db.Host,
                port = db.Port,
                database = db.Database,
                user_name = db.UserName,
                credential_alias = db.CredentialAlias,
                route_id = db.RouteId,
                max_rows = db.MaxRows
            }),
            browser_targets = config.BrowserTargets.Select(browser => new
            {
                id = browser.Id,
                login_url = browser.LoginUrl,
                user_name = browser.UserName,
                credential_alias = browser.CredentialAlias,
                isolation_mode = browser.IsolationMode.ToString(),
                user_name_selector = browser.UserNameSelector,
                password_selector = browser.PasswordSelector,
                submit_selector = browser.SubmitSelector,
                success_selector = browser.SuccessSelector,
                success_url_contains = browser.SuccessUrlContains,
                failure_selector = browser.FailureSelector,
                login_timeout_seconds = browser.LoginTimeoutSeconds
            }),
            policies = config.Policies.Select(policy => new
            {
                id = policy.Id,
                tools = policy.Tools,
                route_ids = policy.RouteIds,
                connection_ids = policy.ConnectionIds,
                browser_target_ids = policy.BrowserTargetIds,
                command_prefixes = policy.CommandPrefixes,
                allow_shell_operators = policy.AllowShellOperators,
                allow_write_sql = policy.AllowWriteSql,
                min_permission = policy.MinPermission.ToString()
            }),
            policy_count = config.Policies.Count
        };
    }

    private object BuildMinimal(string clientProfile, ClientProfile? profile)
    {
        var credentialStatuses = config.Credentials
            .Select(credential => credentials.Exists(credential.Alias) ? "registered" : "missing")
            .ToList();

        return new
        {
            client_profile = clientProfile,
            permission = profile?.Permission.ToString() ?? "Unknown",
            summary_scope = "minimal",
            default_client_profile = config.DefaultClientProfile,
            allowed_tools = profile?.AllowedTools ?? [],
            credentials = new
            {
                total = credentialStatuses.Count,
                registered = credentialStatuses.Count(status => status == "registered"),
                missing = credentialStatuses.Count(status => status == "missing"),
                secret_visible_to_model = false
            },
            routes = config.Routes.Select(route => new
            {
                id = route.Id,
                hop_count = route.SshChain.Count
            }),
            db_targets = config.DbTargets.Select(db => new
            {
                id = db.Id,
                engine = db.Engine.ToString(),
                route_id = db.RouteId,
                max_rows = db.MaxRows
            }),
            browser_targets = config.BrowserTargets.Select(browser => new
            {
                id = browser.Id,
                isolation_mode = browser.IsolationMode.ToString(),
                login_timeout_seconds = browser.LoginTimeoutSeconds
            }),
            ssh_target_count = config.SshTargets.Count,
            policy_count = config.Policies.Count,
            secret_visible_to_model = false
        };
    }
}

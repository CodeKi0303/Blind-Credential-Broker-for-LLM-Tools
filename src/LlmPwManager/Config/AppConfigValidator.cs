namespace LlmPwManager.Config;

internal static class AppConfigValidator
{
    public static IReadOnlyList<string> Validate(AppConfig config)
    {
        var errors = new List<string>();
        RequireDefaultProfile(config, errors);
        RequireUniqueIds("clientProfiles", config.ClientProfiles.Select(p => p.Id), errors);
        RequireUniqueIds("credentials", config.Credentials.Select(c => c.Alias), errors);
        RequireUniqueIds("sshTargets", config.SshTargets.Select(t => t.Id), errors);
        RequireUniqueIds("routes", config.Routes.Select(r => r.Id), errors);
        RequireUniqueIds("dbTargets", config.DbTargets.Select(db => db.Id), errors);
        RequireUniqueIds("browserTargets", config.BrowserTargets.Select(b => b.Id), errors);
        RequireUniqueIds("policies", config.Policies.Select(p => p.Id), errors);

        if (config.SessionIdleTimeoutMinutes < 1)
        {
            errors.Add("sessionIdleTimeoutMinutes must be at least 1");
        }

        ValidateClientProfiles(config, errors);
        ValidateSshTargets(config, errors);
        ValidateRoutes(config, errors);
        ValidateDbTargets(config, errors);
        ValidateBrowserTargets(config, errors);
        ValidatePolicies(config, errors);

        return errors;
    }

    public static void ThrowIfInvalid(AppConfig config)
    {
        var errors = Validate(config);
        if (errors.Count > 0)
        {
            throw new InvalidOperationException("Invalid config: " + string.Join("; ", errors));
        }
    }

    private static void RequireDefaultProfile(AppConfig config, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(config.DefaultClientProfile))
        {
            errors.Add("defaultClientProfile is empty");
            return;
        }

        if (!config.ClientProfiles.Any(p => p.Id == config.DefaultClientProfile))
        {
            errors.Add($"defaultClientProfile references unknown profile '{config.DefaultClientProfile}'");
        }
    }

    private static void RequireUniqueIds(string collection, IEnumerable<string> ids, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in ids)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                errors.Add($"{collection} contains an empty id");
                continue;
            }

            if (!ConfigIdentifier.IsValid(id))
            {
                errors.Add(ConfigIdentifier.Error($"{collection} id", id));
            }

            if (!seen.Add(id))
            {
                errors.Add($"{collection} contains duplicate id '{id}'");
            }
        }
    }

    private static void ValidateClientProfiles(AppConfig config, List<string> errors)
    {
        foreach (var profile in config.ClientProfiles)
        {
            foreach (var tool in profile.AllowedTools)
            {
                RequireKnownTool(tool, $"clientProfile '{profile.Id}' allowedTools", errors);
            }
        }
    }

    private static void ValidateSshTargets(AppConfig config, List<string> errors)
    {
        var credentials = CredentialAliases(config);
        foreach (var target in config.SshTargets)
        {
            if (string.IsNullOrWhiteSpace(target.Host))
            {
                errors.Add($"sshTarget '{target.Id}' has an empty host");
            }

            if (target.Port is < 1 or > 65535)
            {
                errors.Add($"sshTarget '{target.Id}' has invalid port {target.Port}");
            }

            if (string.IsNullOrWhiteSpace(target.UserName))
            {
                errors.Add($"sshTarget '{target.Id}' has an empty userName");
            }

            if (target.AuthMode == SshAuthMode.Password)
            {
                RequireCredential(credentials, target.CredentialAlias, $"sshTarget '{target.Id}'", errors);
            }
            else if (target.AuthMode == SshAuthMode.PrivateKey)
            {
                if (string.IsNullOrWhiteSpace(target.PrivateKeyPath))
                {
                    errors.Add($"sshTarget '{target.Id}' uses privateKey auth but privateKeyPath is empty");
                }

                if (!string.IsNullOrWhiteSpace(target.CredentialAlias))
                {
                    RequireCredential(credentials, target.CredentialAlias, $"sshTarget '{target.Id}' passphrase", errors);
                }
            }
            else
            {
                errors.Add($"sshTarget '{target.Id}' has unsupported authMode '{target.AuthMode}'");
            }
        }
    }

    private static void ValidateRoutes(AppConfig config, List<string> errors)
    {
        var sshTargets = config.SshTargets.Select(t => t.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var route in config.Routes)
        {
            if (route.SshChain.Count == 0)
            {
                errors.Add($"route '{route.Id}' has an empty sshChain");
            }

            foreach (var targetId in route.SshChain)
            {
                if (!sshTargets.Contains(targetId))
                {
                    errors.Add($"route '{route.Id}' references unknown sshTarget '{targetId}'");
                }
            }
        }
    }

    private static void ValidateDbTargets(AppConfig config, List<string> errors)
    {
        var credentials = CredentialAliases(config);
        var routes = config.Routes.Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var db in config.DbTargets)
        {
            if (string.IsNullOrWhiteSpace(db.Host))
            {
                errors.Add($"dbTarget '{db.Id}' has an empty host");
            }

            if (db.Port is < 1 or > 65535)
            {
                errors.Add($"dbTarget '{db.Id}' has invalid port {db.Port}");
            }

            if (string.IsNullOrWhiteSpace(db.UserName))
            {
                errors.Add($"dbTarget '{db.Id}' has an empty userName");
            }

            RequireCredential(credentials, db.CredentialAlias, $"dbTarget '{db.Id}'", errors);

            if (!string.IsNullOrWhiteSpace(db.RouteId) && !routes.Contains(db.RouteId))
            {
                errors.Add($"dbTarget '{db.Id}' references unknown route '{db.RouteId}'");
            }

            if (db.MaxRows < 1)
            {
                errors.Add($"dbTarget '{db.Id}' maxRows must be at least 1");
            }
        }
    }

    private static void ValidateBrowserTargets(AppConfig config, List<string> errors)
    {
        var credentials = CredentialAliases(config);
        foreach (var browser in config.BrowserTargets)
        {
            if (browser.IsolationMode == BrowserIsolationMode.Disabled)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(browser.LoginUrl))
            {
                errors.Add($"browserTarget '{browser.Id}' has an empty loginUrl");
            }

            RequireCredential(credentials, browser.CredentialAlias, $"browserTarget '{browser.Id}'", errors);

            if (!Uri.TryCreate(browser.LoginUrl, UriKind.Absolute, out var loginUri) ||
                loginUri.Scheme is not ("http" or "https"))
            {
                errors.Add($"browserTarget '{browser.Id}' loginUrl must be an absolute http or https URL");
            }

            if (string.IsNullOrWhiteSpace(browser.UserName))
            {
                errors.Add($"browserTarget '{browser.Id}' has an empty userName");
            }

            if (browser.IsolationMode == BrowserIsolationMode.ManagedProfile)
            {
                RequireBrowserSelector(browser.UserNameSelector, "userNameSelector", browser.Id, errors);
                RequireBrowserSelector(browser.PasswordSelector, "passwordSelector", browser.Id, errors);
                RequireBrowserSelector(browser.SubmitSelector, "submitSelector", browser.Id, errors);

                if (string.IsNullOrWhiteSpace(browser.SuccessSelector) &&
                    string.IsNullOrWhiteSpace(browser.SuccessUrlContains))
                {
                    errors.Add($"browserTarget '{browser.Id}' must define successSelector or successUrlContains");
                }

                if (browser.LoginTimeoutSeconds < 5)
                {
                    errors.Add($"browserTarget '{browser.Id}' loginTimeoutSeconds must be at least 5");
                }
            }
        }
    }

    private static void RequireBrowserSelector(string selector, string property, string id, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            errors.Add($"browserTarget '{id}' has an empty {property}");
        }
    }

    private static void ValidatePolicies(AppConfig config, List<string> errors)
    {
        var routes = config.Routes.Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var dbTargets = config.DbTargets.Select(db => db.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var browserTargets = config.BrowserTargets.Select(browser => browser.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var policy in config.Policies)
        {
            foreach (var tool in policy.Tools)
            {
                RequireKnownTool(tool, $"policy '{policy.Id}' tools", errors);
            }

            if (AppliesToTool(policy.Tools, "ssh_run") &&
                policy.MinPermission != PermissionProfile.Full &&
                policy.CommandPrefixes.Count == 0)
            {
                errors.Add($"policy '{policy.Id}' allows ssh_run for non-full profiles and must define commandPrefixes");
            }

            foreach (var routeId in policy.RouteIds)
            {
                if (!routes.Contains(routeId))
                {
                    errors.Add($"policy '{policy.Id}' references unknown route '{routeId}'");
                }
            }

            foreach (var connectionId in policy.ConnectionIds)
            {
                if (!dbTargets.Contains(connectionId))
                {
                    errors.Add($"policy '{policy.Id}' references unknown dbTarget '{connectionId}'");
                }
            }

            foreach (var browserTargetId in policy.BrowserTargetIds)
            {
                if (!browserTargets.Contains(browserTargetId))
                {
                    errors.Add($"policy '{policy.Id}' references unknown browserTarget '{browserTargetId}'");
                }
            }
        }
    }

    private static bool AppliesToTool(List<string> tools, string tool) =>
        tools.Count == 0 || tools.Contains(tool, StringComparer.OrdinalIgnoreCase);

    private static HashSet<string> CredentialAliases(AppConfig config)
    {
        return config.Credentials.Select(c => c.Alias).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static void RequireCredential(HashSet<string> credentials, string alias, string owner, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            errors.Add($"{owner} has an empty credentialAlias");
            return;
        }

        if (!credentials.Contains(alias))
        {
            errors.Add($"{owner} references unknown credential '{alias}'");
        }
    }

    private static void RequireKnownTool(string tool, string owner, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(tool))
        {
            errors.Add($"{owner} contains an empty tool name");
            return;
        }

        if (!KnownTools.Contains(tool))
        {
            errors.Add($"{owner} references unknown tool '{tool}'");
        }
    }

    private static readonly HashSet<string> KnownTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "ssh_run",
        "ssh_register",
        "ssh_open_session",
        "session_list",
        "session_close",
        "browser_login",
        "browser_register",
        "db_query",
        "db_register",
        "route_test",
        "policy_check",
        "credential_status",
        "forget_credential",
        "config_summary",
        "audit_tail"
    };
}

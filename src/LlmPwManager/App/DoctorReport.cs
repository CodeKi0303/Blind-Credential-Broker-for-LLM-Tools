using LlmPwManager.Browser;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Mcp;
using LlmPwManager.Security;

namespace LlmPwManager.App;

internal static class DoctorReport
{
    public static object Build(
        AppConfig config,
        ICredentialStore credentials,
        string configPath,
        string auditPath,
        string appDirectory)
    {
        var configErrors = ConfigErrorSanitizer.Sanitize(AppConfigValidator.Validate(config));
        var credentialItems = config.Credentials.Select(credential => new
        {
            alias = Sanitize(credential.Alias),
            label = Sanitize(credential.Label),
            user_name = Sanitize(credential.UserName),
            status = credentials.Exists(credential.Alias) ? "registered" : "missing",
            secret_visible_to_model = false
        }).ToList();
        var missingCredentials = credentialItems.Count(item => item.status == "missing");
        var edgePath = EdgeLocator.FindExecutable();
        var activeBrowserTargets = config.BrowserTargets
            .Where(target => target.IsolationMode == BrowserIsolationMode.ManagedProfile)
            .Select(target => Sanitize(target.Id))
            .ToList();
        var mcpConfig = McpClientConfigFactory.Create("generic", "llm-pw-manager", appDirectory, config.DefaultClientProfile);
        var policyCoverage = BuildPolicyCoverage(config);
        var checks = new List<DoctorCheck>
        {
            new(
                "config",
                configErrors.Count == 0 ? "ok" : "error",
                configErrors.Count == 0 ? "Config is valid." : "Config has validation errors.",
                configErrors),
            new(
                "credential_aliases",
                missingCredentials == 0 ? "ok" : "warning",
                missingCredentials == 0 ? "All configured credential aliases are registered." : $"{missingCredentials} credential alias(es) are missing.",
                credentialItems),
            new(
                "edge",
                activeBrowserTargets.Count == 0 || edgePath is not null ? "ok" : "warning",
                activeBrowserTargets.Count == 0
                    ? "No managed browser targets configured."
                    : edgePath is not null
                        ? "Microsoft Edge was found."
                        : "Managed browser targets need Microsoft Edge, but Edge was not found.",
                new { edge_path = edgePath, managed_browser_targets = activeBrowserTargets }),
            new(
                "mcp_config",
                "ok",
                "MCP stdio configuration can be generated.",
                mcpConfig),
            new(
                "policy_coverage",
                policyCoverage.HasWarnings ? "warning" : "ok",
                policyCoverage.HasWarnings
                    ? "Some limited-profile targets do not have matching policy rules."
                    : "Limited-profile target policy coverage looks complete.",
                policyCoverage.Data),
            new(
                "paths",
                Directory.Exists(appDirectory) ? "ok" : "error",
                Directory.Exists(appDirectory) ? "App directory is writable." : "App directory does not exist.",
                new
                {
                    app_directory = appDirectory,
                    config_path = configPath,
                    audit_path = auditPath,
                    session_idle_timeout_minutes = config.SessionIdleTimeoutMinutes
                })
        };

        return new
        {
            ok = checks.All(check => check.Status != "error"),
            status = checks.Any(check => check.Status == "error")
                ? "error"
                : checks.Any(check => check.Status == "warning")
                    ? "warning"
                    : "ok",
            checks,
            secret_visible_to_model = false
        };
    }

    private static PolicyCoverage BuildPolicyCoverage(AppConfig config)
    {
        var limitedProfiles = config.ClientProfiles
            .Where(profile => profile.Permission == PermissionProfile.Limited)
            .Select(profile => Sanitize(profile.Id))
            .ToList();

        var checkSshRun = limitedProfiles.Count > 0 && LimitedProfileAllows(config, "ssh_run");
        var checkRouteTest = limitedProfiles.Count > 0 && LimitedProfileAllows(config, "route_test");
        var checkDbQuery = limitedProfiles.Count > 0 && LimitedProfileAllows(config, "db_query");
        var checkBrowserLogin = limitedProfiles.Count > 0 && LimitedProfileAllows(config, "browser_login");

        var missingSshRunRoutes = checkSshRun
            ? config.Routes
                .Where(route => !HasMatchingPolicy(config, "ssh_run", routeId: route.Id))
                .Select(route => Sanitize(route.Id))
                .ToList()
            : [];
        var missingRouteTestRoutes = checkRouteTest
            ? config.Routes
                .Where(route => !HasMatchingPolicy(config, "route_test", routeId: route.Id))
                .Select(route => Sanitize(route.Id))
                .ToList()
            : [];
        var missingDbConnections = checkDbQuery
            ? config.DbTargets
                .Where(db => !HasMatchingPolicy(config, "db_query", connectionId: db.Id))
                .Select(db => Sanitize(db.Id))
                .ToList()
            : [];
        var missingBrowserTargets = checkBrowserLogin
            ? config.BrowserTargets
                .Where(browser => browser.IsolationMode != BrowserIsolationMode.Disabled)
                .Where(browser => !HasMatchingPolicy(config, "browser_login", browserTargetId: browser.Id))
                .Select(browser => Sanitize(browser.Id))
                .ToList()
            : [];

        var hasWarnings = missingSshRunRoutes.Count > 0 ||
            missingRouteTestRoutes.Count > 0 ||
            missingDbConnections.Count > 0 ||
            missingBrowserTargets.Count > 0;

        return new PolicyCoverage(
            hasWarnings,
            new
            {
                limited_profiles = limitedProfiles,
                ssh_run_missing_routes = missingSshRunRoutes,
                route_test_missing_routes = missingRouteTestRoutes,
                db_query_missing_connections = missingDbConnections,
                browser_login_missing_targets = missingBrowserTargets
            });
    }

    private static bool LimitedProfileAllows(AppConfig config, string toolName)
    {
        return config.ClientProfiles.Any(profile =>
            profile.Permission == PermissionProfile.Limited &&
            (profile.AllowedTools.Count == 0 || profile.AllowedTools.Contains(toolName, StringComparer.OrdinalIgnoreCase)));
    }

    private static bool HasMatchingPolicy(
        AppConfig config,
        string toolName,
        string? routeId = null,
        string? connectionId = null,
        string? browserTargetId = null)
    {
        return config.Policies.Any(policy =>
            Rank(policy.MinPermission) <= Rank(PermissionProfile.Limited) &&
            Matches(policy.Tools, toolName) &&
            Matches(policy.RouteIds, routeId) &&
            Matches(policy.ConnectionIds, connectionId) &&
            Matches(policy.BrowserTargetIds, browserTargetId));
    }

    private static bool Matches(List<string> values, string? actual)
    {
        return values.Count == 0 ||
            (actual is not null && values.Contains(actual, StringComparer.OrdinalIgnoreCase));
    }

    private static int Rank(PermissionProfile profile) => profile switch
    {
        PermissionProfile.DenyByDefault => 0,
        PermissionProfile.Approval => 1,
        PermissionProfile.Limited => 2,
        PermissionProfile.Full => 3,
        _ => 0
    };

    private static string Sanitize(string value) => SecretRedactor.RedactSecretLikeValues(value);
}

internal sealed record DoctorCheck(string Name, string Status, string Message, object? Data);

internal sealed record PolicyCoverage(bool HasWarnings, object Data);

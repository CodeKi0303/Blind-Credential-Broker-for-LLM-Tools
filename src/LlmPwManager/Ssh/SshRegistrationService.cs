using LlmPwManager.Config;
using LlmPwManager.Credentials;
using Renci.SshNet;

namespace LlmPwManager.Ssh;

internal interface ISshRegistrationService
{
    Task<SshRegistrationResult> RegisterDirectPasswordAsync(SshRegistrationRequest request, CancellationToken cancellationToken);
}

internal sealed class SshRegistrationService(
    AppConfig config,
    string configPath,
    CredentialResolver credentials) : ISshRegistrationService
{
    public async Task<SshRegistrationResult> RegisterDirectPasswordAsync(SshRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (config.Routes.Any(route => route.Id.Equals(request.RouteId, StringComparison.OrdinalIgnoreCase)))
        {
            return new SshRegistrationResult("already_configured", request.RouteId, request.RouteId, $"{request.RouteId}-password", false);
        }

        var latestConfig = AppConfigStore.LoadOrCreate(configPath);
        if (latestConfig.Routes.Any(route => route.Id.Equals(request.RouteId, StringComparison.OrdinalIgnoreCase)))
        {
            AppConfigStore.CopyInto(config, latestConfig);
            return new SshRegistrationResult("already_configured", request.RouteId, request.RouteId, $"{request.RouteId}-password", false);
        }

        var targetId = request.RouteId;
        var credentialAlias = $"{request.RouteId}-password";
        var policyId = $"{request.RouteId}-ssh-policy";

        await credentials.ResolveAsync(
            credentialAlias,
            $"SSH password for {request.UserName}@{request.Host}:{request.Port}",
            request.UserName,
            candidate => TestDirectSshAsync(request.Host, request.Port, request.UserName, candidate),
            cancellationToken);

        var status = "registered";
        var saved = AppConfigStore.Update(configPath, latest =>
        {
            if (latest.Routes.Any(route => route.Id.Equals(request.RouteId, StringComparison.OrdinalIgnoreCase)))
            {
                status = "already_configured";
                return;
            }

            AddRegistration(latest);
            AppConfigValidator.ThrowIfInvalid(latest);
        });
        AppConfigStore.CopyInto(config, saved);
        return new SshRegistrationResult(status, request.RouteId, targetId, credentialAlias, true);

        void AddRegistration(AppConfig targetConfig)
        {
            ConfigMutator.AddCredential(targetConfig, credentialAlias, request.UserName, $"SSH password for {request.UserName}@{request.Host}");
            ConfigMutator.AddSshTarget(targetConfig, targetId, request.Host, request.Port, request.UserName, SshAuthMode.Password, credentialAlias, null);
            ConfigMutator.AddRoute(targetConfig, request.RouteId, [targetId]);

            if (request.CommandPrefixes.Count > 0)
            {
                ConfigMutator.AddSshPolicy(
                    targetConfig,
                    policyId,
                    [request.RouteId],
                    request.CommandPrefixes,
                    allowShellOperators: false,
                    PermissionProfile.Limited);
            }
        }
    }

    private static Task<CredentialTestResult> TestDirectSshAsync(string host, int port, string userName, string password)
    {
        return Task.Run(() =>
        {
            try
            {
                var auth = new PasswordAuthenticationMethod(userName, password);
                var connectionInfo = new ConnectionInfo(host, port, userName, auth)
                {
                    Timeout = TimeSpan.FromSeconds(20)
                };
                using var client = new SshClient(connectionInfo);
                client.Connect();
                client.Disconnect();
                return new CredentialTestResult(true);
            }
            catch
            {
                return new CredentialTestResult(false, "SSH authentication failed.");
            }
        });
    }
}

internal sealed record SshRegistrationRequest(
    string RouteId,
    string Host,
    int Port,
    string UserName,
    string Purpose,
    IReadOnlyList<string> CommandPrefixes,
    string ClientProfile);

internal sealed record SshRegistrationResult(
    string Status,
    string RouteId,
    string TargetId,
    string CredentialAlias,
    bool PromptShown);

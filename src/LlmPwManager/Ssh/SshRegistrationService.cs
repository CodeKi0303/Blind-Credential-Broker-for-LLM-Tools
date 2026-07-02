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

        var targetId = request.RouteId;
        var credentialAlias = $"{request.RouteId}-password";
        var policyId = $"{request.RouteId}-ssh-policy";

        var addedCredential = false;
        var addedTarget = false;
        var addedRoute = false;
        var addedPolicy = false;
        var credentialStored = false;

        try
        {
            ConfigMutator.AddCredential(config, credentialAlias, request.UserName, $"SSH password for {request.UserName}@{request.Host}");
            addedCredential = true;
            ConfigMutator.AddSshTarget(config, targetId, request.Host, request.Port, request.UserName, SshAuthMode.Password, credentialAlias, null);
            addedTarget = true;
            ConfigMutator.AddRoute(config, request.RouteId, [targetId]);
            addedRoute = true;

            if (request.CommandPrefixes.Count > 0)
            {
                ConfigMutator.AddSshPolicy(
                    config,
                    policyId,
                    [request.RouteId],
                    request.CommandPrefixes,
                    allowShellOperators: false,
                    PermissionProfile.Limited);
                addedPolicy = true;
            }

            AppConfigValidator.ThrowIfInvalid(config);

            await credentials.ResolveAsync(
                credentialAlias,
                $"SSH password for {request.UserName}@{request.Host}:{request.Port}",
                request.UserName,
                candidate => TestDirectSshAsync(request.Host, request.Port, request.UserName, candidate),
                cancellationToken);
            credentialStored = true;

            AppConfigStore.Save(configPath, config);
            return new SshRegistrationResult("registered", request.RouteId, targetId, credentialAlias, true);
        }
        catch
        {
            if (addedPolicy)
            {
                config.Policies.RemoveAll(policy => policy.Id.Equals(policyId, StringComparison.OrdinalIgnoreCase));
            }

            if (addedRoute)
            {
                config.Routes.RemoveAll(route => route.Id.Equals(request.RouteId, StringComparison.OrdinalIgnoreCase));
            }

            if (addedTarget)
            {
                config.SshTargets.RemoveAll(target => target.Id.Equals(targetId, StringComparison.OrdinalIgnoreCase));
            }

            if (addedCredential)
            {
                config.Credentials.RemoveAll(credential => credential.Alias.Equals(credentialAlias, StringComparison.OrdinalIgnoreCase));
            }

            if (credentialStored)
            {
                credentials.Forget(credentialAlias);
            }

            throw;
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

using LlmPwManager.Config;
using LlmPwManager.Credentials;

namespace LlmPwManager.Db;

internal interface IDbRegistrationService
{
    Task<DbRegistrationResult> RegisterAsync(DbRegistrationRequest request, CancellationToken cancellationToken);
}

internal sealed class DbRegistrationService(
    AppConfig config,
    string configPath,
    DbExecutor db,
    CredentialResolver credentials) : IDbRegistrationService
{
    public async Task<DbRegistrationResult> RegisterAsync(DbRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (config.DbTargets.Any(target => target.Id.Equals(request.ConnectionId, StringComparison.OrdinalIgnoreCase)))
        {
            return new DbRegistrationResult("already_configured", request.ConnectionId, $"{request.ConnectionId}-password", false);
        }

        var latestConfig = AppConfigStore.LoadOrCreate(configPath);
        if (latestConfig.DbTargets.Any(target => target.Id.Equals(request.ConnectionId, StringComparison.OrdinalIgnoreCase)))
        {
            AppConfigStore.CopyInto(config, latestConfig);
            return new DbRegistrationResult("already_configured", request.ConnectionId, $"{request.ConnectionId}-password", false);
        }

        var credentialAlias = $"{request.ConnectionId}-password";
        var policyId = $"{request.ConnectionId}-db-policy";
        var addedCredential = false;
        var addedTarget = false;
        var addedPolicy = false;

        try
        {
            ConfigMutator.AddCredential(config, credentialAlias, request.UserName, $"DB password for {request.UserName}@{request.Host}/{request.Database}");
            addedCredential = true;
            ConfigMutator.AddDbTarget(
                config,
                request.ConnectionId,
                request.Engine,
                request.Host,
                request.Port,
                request.Database,
                request.UserName,
                credentialAlias,
                request.RouteId,
                request.MaxRows);
            addedTarget = true;
            ConfigMutator.AddDbPolicy(
                config,
                policyId,
                [request.ConnectionId],
                request.AllowWriteSql,
                PermissionProfile.Limited);
            addedPolicy = true;

            AppConfigValidator.ThrowIfInvalid(config);
            await db.QueryAsync(request.ConnectionId, "select 1", new Dictionary<string, object?>(), cancellationToken);

            var status = "registered";
            var saved = AppConfigStore.Update(configPath, latest =>
            {
                if (latest.DbTargets.Any(target => target.Id.Equals(request.ConnectionId, StringComparison.OrdinalIgnoreCase)))
                {
                    status = "already_configured";
                    return;
                }

                AddRegistration(latest);
                AppConfigValidator.ThrowIfInvalid(latest);
            });
            AppConfigStore.CopyInto(config, saved);
            return new DbRegistrationResult(status, request.ConnectionId, credentialAlias, true);
        }
        catch
        {
            if (addedPolicy)
            {
                config.Policies.RemoveAll(policy => policy.Id.Equals(policyId, StringComparison.OrdinalIgnoreCase));
            }

            if (addedTarget)
            {
                config.DbTargets.RemoveAll(target => target.Id.Equals(request.ConnectionId, StringComparison.OrdinalIgnoreCase));
            }

            if (addedCredential)
            {
                config.Credentials.RemoveAll(credential => credential.Alias.Equals(credentialAlias, StringComparison.OrdinalIgnoreCase));
                credentials.Forget(credentialAlias);
            }

            throw;
        }

        void AddRegistration(AppConfig targetConfig)
        {
            ConfigMutator.AddCredential(targetConfig, credentialAlias, request.UserName, $"DB password for {request.UserName}@{request.Host}/{request.Database}");
            ConfigMutator.AddDbTarget(
                targetConfig,
                request.ConnectionId,
                request.Engine,
                request.Host,
                request.Port,
                request.Database,
                request.UserName,
                credentialAlias,
                request.RouteId,
                request.MaxRows);
            ConfigMutator.AddDbPolicy(
                targetConfig,
                policyId,
                [request.ConnectionId],
                request.AllowWriteSql,
                PermissionProfile.Limited);
        }
    }
}

internal sealed record DbRegistrationRequest(
    string ConnectionId,
    DbEngine Engine,
    string Host,
    int Port,
    string Database,
    string UserName,
    string? RouteId,
    int MaxRows,
    bool AllowWriteSql,
    string Purpose,
    string ClientProfile);

internal sealed record DbRegistrationResult(
    string Status,
    string ConnectionId,
    string CredentialAlias,
    bool PromptShown);

using LlmPwManager.Config;
using LlmPwManager.Credentials;

namespace LlmPwManager.Browser;

internal interface IBrowserRegistrationService
{
    Task<BrowserRegistrationResult> RegisterAsync(BrowserRegistrationRequest request, CancellationToken cancellationToken);
}

internal sealed class BrowserRegistrationService(
    AppConfig config,
    string configPath,
    IBrowserLoginExecutor browser,
    CredentialResolver credentials) : IBrowserRegistrationService
{
    public async Task<BrowserRegistrationResult> RegisterAsync(BrowserRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (config.BrowserTargets.Any(target => target.Id.Equals(request.TargetId, StringComparison.OrdinalIgnoreCase)))
        {
            return new BrowserRegistrationResult(true, "already_configured", request.TargetId, $"{request.TargetId}-password", false);
        }

        var latestConfig = AppConfigStore.LoadOrCreate(configPath);
        if (latestConfig.BrowserTargets.Any(target => target.Id.Equals(request.TargetId, StringComparison.OrdinalIgnoreCase)))
        {
            AppConfigStore.CopyInto(config, latestConfig);
            return new BrowserRegistrationResult(true, "already_configured", request.TargetId, $"{request.TargetId}-password", false);
        }

        var credentialAlias = $"{request.TargetId}-password";
        var policyId = $"{request.TargetId}-browser-policy";
        var addedCredential = false;
        var addedTarget = false;
        var addedPolicy = false;

        try
        {
            ConfigMutator.AddCredential(config, credentialAlias, request.UserName, $"Browser password for {request.UserName}");
            addedCredential = true;
            ConfigMutator.AddBrowserTarget(
                config,
                request.TargetId,
                request.LoginUrl,
                request.UserName,
                credentialAlias,
                BrowserIsolationMode.ManagedProfile,
                request.UserNameSelector,
                request.PasswordSelector,
                request.SubmitSelector,
                request.SuccessSelector,
                request.SuccessUrlContains,
                request.FailureSelector,
                request.LoginTimeoutSeconds);
            addedTarget = true;
            ConfigMutator.AddBrowserPolicy(config, policyId, [request.TargetId], PermissionProfile.Limited);
            addedPolicy = true;

            AppConfigValidator.ThrowIfInvalid(config);
            var target = config.BrowserTargets.Single(target => target.Id.Equals(request.TargetId, StringComparison.OrdinalIgnoreCase));
            var result = await browser.LoginAsync(target, cancellationToken);
            if (!result.Success)
            {
                Rollback();
                return new BrowserRegistrationResult(false, result.Status, request.TargetId, credentialAlias, true, result.SafeMessage);
            }

            var status = "registered";
            var saved = AppConfigStore.Update(configPath, latest =>
            {
                if (latest.BrowserTargets.Any(target => target.Id.Equals(request.TargetId, StringComparison.OrdinalIgnoreCase)))
                {
                    status = "already_configured";
                    return;
                }

                AddRegistration(latest);
                AppConfigValidator.ThrowIfInvalid(latest);
            });
            AppConfigStore.CopyInto(config, saved);
            return new BrowserRegistrationResult(true, status, request.TargetId, credentialAlias, true);
        }
        catch
        {
            Rollback();
            throw;
        }

        void AddRegistration(AppConfig targetConfig)
        {
            ConfigMutator.AddCredential(targetConfig, credentialAlias, request.UserName, $"Browser password for {request.UserName}");
            ConfigMutator.AddBrowserTarget(
                targetConfig,
                request.TargetId,
                request.LoginUrl,
                request.UserName,
                credentialAlias,
                BrowserIsolationMode.ManagedProfile,
                request.UserNameSelector,
                request.PasswordSelector,
                request.SubmitSelector,
                request.SuccessSelector,
                request.SuccessUrlContains,
                request.FailureSelector,
                request.LoginTimeoutSeconds);
            ConfigMutator.AddBrowserPolicy(targetConfig, policyId, [request.TargetId], PermissionProfile.Limited);
        }

        void Rollback()
        {
            if (addedPolicy)
            {
                config.Policies.RemoveAll(policy => policy.Id.Equals(policyId, StringComparison.OrdinalIgnoreCase));
            }

            if (addedTarget)
            {
                config.BrowserTargets.RemoveAll(target => target.Id.Equals(request.TargetId, StringComparison.OrdinalIgnoreCase));
            }

            if (addedCredential)
            {
                config.Credentials.RemoveAll(credential => credential.Alias.Equals(credentialAlias, StringComparison.OrdinalIgnoreCase));
                credentials.Forget(credentialAlias);
            }
        }
    }
}

internal sealed record BrowserRegistrationRequest(
    string TargetId,
    string LoginUrl,
    string UserName,
    string UserNameSelector,
    string PasswordSelector,
    string SubmitSelector,
    string? SuccessSelector,
    string? SuccessUrlContains,
    string? FailureSelector,
    int LoginTimeoutSeconds,
    string Purpose,
    string ClientProfile);

internal sealed record BrowserRegistrationResult(
    bool Success,
    string Status,
    string TargetId,
    string CredentialAlias,
    bool PromptShown,
    string? SafeMessage = null);

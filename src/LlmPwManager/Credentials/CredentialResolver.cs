using LlmPwManager.Ui;

namespace LlmPwManager.Credentials;

internal sealed class CredentialResolver(
    ICredentialStore store,
    ICredentialPrompt prompt,
    int maxAttempts)
{
    public bool Exists(string alias) => store.Exists(alias);

    public bool Forget(string alias)
    {
        var existed = store.Exists(alias);
        store.DeleteSecret(alias);
        return existed;
    }

    public async Task<string> ResolveAsync(
        string alias,
        string label,
        string userName,
        Func<string, Task<CredentialTestResult>> tester,
        CancellationToken cancellationToken)
    {
        var existing = store.GetSecret(alias);
        string? lastSafeFailure = null;
        if (!string.IsNullOrEmpty(existing))
        {
            var existingResult = await tester(existing);
            if (existingResult.Success)
            {
                return existing;
            }

            lastSafeFailure = SanitizeFailureMessage(existingResult.SafeMessage, existing);
            store.DeleteSecret(alias);
        }

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var reason = attempt == 1
                ? FirstPromptReason(lastSafeFailure)
                : RetryPromptReason(lastSafeFailure);

            var secret = prompt.RequestPassword(alias, label, userName, reason);
            if (secret is null)
            {
                throw new CredentialUnavailableException(alias, "User cancelled credential entry.");
            }

            var result = await tester(secret);
            if (result.Success)
            {
                store.SaveSecret(alias, secret);
                return secret;
            }

            lastSafeFailure = SanitizeFailureMessage(result.SafeMessage, secret);
        }

        throw new CredentialUnavailableException(alias, "Credential test failed too many times.");
    }

    private static string FirstPromptReason(string? lastSafeFailure)
    {
        return string.IsNullOrWhiteSpace(lastSafeFailure)
            ? "Credential is missing or no longer valid."
            : $"Stored credential test failed: {lastSafeFailure}. Please enter the credential again.";
    }

    private static string RetryPromptReason(string? lastSafeFailure)
    {
        return string.IsNullOrWhiteSpace(lastSafeFailure)
            ? "Connection test failed. Please try again."
            : $"Connection test failed: {lastSafeFailure}. Please try again.";
    }

    private static string? SanitizeFailureMessage(string? message, string secret)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return null;
        }

        var sanitized = message.Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (!string.IsNullOrEmpty(secret))
        {
            sanitized = sanitized.Replace(secret, "[REDACTED]", StringComparison.Ordinal);
        }

        return sanitized.Length <= 200 ? sanitized : sanitized[..200] + "...";
    }
}

internal sealed record CredentialTestResult(bool Success, string? SafeMessage = null);

internal sealed class CredentialUnavailableException(string alias, string message) : Exception(message)
{
    public string Alias { get; } = alias;
}

using LlmPwManager.Security;

namespace LlmPwManager.App;

internal static class ConfigErrorSanitizer
{
    public static IReadOnlyList<string> Sanitize(IEnumerable<string> errors)
    {
        return errors
            .Select(SecretRedactor.RedactSecretLikeValues)
            .ToList();
    }
}

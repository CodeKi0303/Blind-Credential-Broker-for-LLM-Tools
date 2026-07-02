using LlmPwManager.Security;

namespace LlmPwManager.Audit;

internal static class AuditSanitizer
{
    private const int MaxLength = 500;

    public static string Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        var sanitized = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        sanitized = SecretRedactor.RedactSecretLikeValues(sanitized);
        return sanitized.Length <= MaxLength ? sanitized : sanitized[..MaxLength] + "...";
    }
}

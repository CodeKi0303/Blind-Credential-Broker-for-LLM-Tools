using System.Text.RegularExpressions;

namespace LlmPwManager.Security;

internal sealed class SecretRedactor
{
    private static readonly Regex AssignmentSecretPattern = new(
        @"\b(?<key>[a-z0-9_.-]*(?:password|passwd|pwd|passphrase|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|secret)[a-z0-9_.-]*)\s*[:=]\s*(?<value>""[^""]*""|'[^']*'|[^\s;&|,""']+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private static readonly Regex UriUserInfoPattern = new(
        @"(?<scheme>[a-z][a-z0-9+.-]*://)(?<userinfo>[^/@\s:]+:[^/@\s]+)@",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    public string Redact(string? value, IEnumerable<string>? secrets = null)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        var redacted = value;
        if (secrets is not null)
        {
            foreach (var secret in secrets.Where(s => !string.IsNullOrEmpty(s)).Distinct())
            {
                redacted = redacted.Replace(secret, "[REDACTED]", StringComparison.Ordinal);
            }
        }

        return RedactSecretLikeValues(redacted);
    }

    public static string RedactSecretLikeValues(string value)
    {
        var redacted = UriUserInfoPattern.Replace(value, "${scheme}[REDACTED]@");
        return AssignmentSecretPattern.Replace(redacted, match => $"{match.Groups["key"].Value}=[REDACTED]");
    }
}

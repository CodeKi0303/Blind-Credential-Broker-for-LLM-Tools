using LlmPwManager.Security;

namespace LlmPwManager.Db;

internal static class DbResultSanitizer
{
    private static readonly string[] SensitiveColumnMarkers =
    [
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "token",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential"
    ];

    public static DbQueryResult Sanitize(DbQueryResult result)
    {
        var redactedColumns = result.Columns
            .Where(IsSensitiveColumn)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var sensitive = redactedColumns.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var rows = result.Rows.Select(row =>
        {
            var sanitized = new Dictionary<string, object?>(row, StringComparer.OrdinalIgnoreCase);
            foreach (var (column, value) in row)
            {
                if (value is null)
                {
                    continue;
                }

                if (sensitive.Contains(column))
                {
                    sanitized[column] = "[REDACTED]";
                }
                else if (value is string text)
                {
                    sanitized[column] = SecretRedactor.RedactSecretLikeValues(text);
                }
            }

            return sanitized;
        }).ToList();

        return result with
        {
            Rows = rows,
            RedactedColumns = redactedColumns
        };
    }

    private static bool IsSensitiveColumn(string column)
    {
        var normalized = column.Replace("-", "_", StringComparison.Ordinal).ToLowerInvariant();
        return SensitiveColumnMarkers.Any(marker => normalized.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }
}

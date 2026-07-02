using System.Text.Json;

namespace LlmPwManager.Audit;

internal sealed class AuditLogger(string path)
{
    private readonly object gate = new();

    public void Record(string tool, string clientProfile, string target, string action, string status, string? reason = null)
    {
        var entry = new AuditEntry(
            DateTimeOffset.UtcNow,
            AuditSanitizer.Sanitize(tool),
            AuditSanitizer.Sanitize(clientProfile),
            AuditSanitizer.Sanitize(target),
            AuditSanitizer.Sanitize(action),
            AuditSanitizer.Sanitize(status),
            reason is null ? null : AuditSanitizer.Sanitize(reason));

        var line = JsonSerializer.Serialize(entry, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        lock (gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, line + Environment.NewLine);
        }
    }
}

internal sealed record AuditEntry(
    DateTimeOffset Timestamp,
    string Tool,
    string ClientProfile,
    string Target,
    string Action,
    string Status,
    string? Reason);

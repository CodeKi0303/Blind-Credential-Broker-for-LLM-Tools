using System.Text.Json;

namespace LlmPwManager.Audit;

internal sealed class AuditLogReader(string path)
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public IReadOnlyList<AuditEntry> Tail(int limit)
    {
        limit = Math.Clamp(limit, 1, 500);
        if (!File.Exists(path))
        {
            return [];
        }

        var queue = new Queue<AuditEntry>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            AuditEntry? entry;
            try
            {
                entry = JsonSerializer.Deserialize<AuditEntry>(line, Options);
            }
            catch (JsonException)
            {
                continue;
            }

            if (entry is null)
            {
                continue;
            }

            queue.Enqueue(entry);
            while (queue.Count > limit)
            {
                queue.Dequeue();
            }
        }

        return queue.ToList();
    }
}

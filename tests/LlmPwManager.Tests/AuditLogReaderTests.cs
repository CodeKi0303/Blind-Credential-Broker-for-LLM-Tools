using LlmPwManager.Audit;

namespace LlmPwManager.Tests;

public sealed class AuditLogReaderTests
{
    [Fact]
    public void TailReturnsMostRecentEntries()
    {
        var path = Path.Combine(Path.GetTempPath(), "llm-pw-audit-" + Guid.NewGuid().ToString("N") + ".jsonl");
        var logger = new AuditLogger(path);
        logger.Record("tool-a", "limited", "target-a", "action-a", "ok");
        logger.Record("tool-b", "limited", "target-b", "action-b", "denied", "reason");
        logger.Record("tool-c", "limited", "target-c", "action-c", "ok");

        var entries = new AuditLogReader(path).Tail(2);

        Assert.Equal(2, entries.Count);
        Assert.Equal("tool-b", entries[0].Tool);
        Assert.Equal("tool-c", entries[1].Tool);
    }

    [Fact]
    public void TailSkipsMalformedLines()
    {
        var path = Path.Combine(Path.GetTempPath(), "llm-pw-audit-" + Guid.NewGuid().ToString("N") + ".jsonl");
        File.WriteAllLines(path,
        [
            "{ not-json",
            """{"timestamp":"2026-01-01T00:00:00Z","tool":"ssh_run","clientProfile":"limited","target":"route","action":"uptime","status":"ok","reason":null}"""
        ]);

        var entries = new AuditLogReader(path).Tail(10);

        Assert.Single(entries);
        Assert.Equal("ssh_run", entries[0].Tool);
    }

    [Fact]
    public void LoggerRedactsSecretLikeValuesBeforeWriting()
    {
        var path = Path.Combine(Path.GetTempPath(), "llm-pw-audit-" + Guid.NewGuid().ToString("N") + ".jsonl");
        var logger = new AuditLogger(path);

        logger.Record(
            "ssh_run",
            "limited",
            "target",
            "PGPASSWORD=super-secret psql postgresql://user:uri-secret@db/app --set token=abc123 access_key=access-secret private_key=private-secret credential=credential-secret",
            "denied",
            "api_key='key-secret' clientSecret=client-secret failed");

        var entry = new AuditLogReader(path).Tail(1).Single();
        var serialized = string.Join(" ", entry.Action, entry.Reason);

        Assert.Contains("PGPASSWORD=[REDACTED]", entry.Action);
        Assert.Contains("postgresql://[REDACTED]@db/app", entry.Action);
        Assert.Contains("token=[REDACTED]", entry.Action);
        Assert.Contains("access_key=[REDACTED]", entry.Action);
        Assert.Contains("private_key=[REDACTED]", entry.Action);
        Assert.Contains("credential=[REDACTED]", entry.Action);
        Assert.Contains("api_key=[REDACTED]", entry.Reason);
        Assert.Contains("clientSecret=[REDACTED]", entry.Reason);
        Assert.DoesNotContain("super-secret", serialized);
        Assert.DoesNotContain("uri-secret", serialized);
        Assert.DoesNotContain("abc123", serialized);
        Assert.DoesNotContain("access-secret", serialized);
        Assert.DoesNotContain("private-secret", serialized);
        Assert.DoesNotContain("credential-secret", serialized);
        Assert.DoesNotContain("key-secret", serialized);
        Assert.DoesNotContain("client-secret", serialized);
    }

    [Fact]
    public void LoggerNormalizesNewlinesAndTruncatesLongActions()
    {
        var path = Path.Combine(Path.GetTempPath(), "llm-pw-audit-" + Guid.NewGuid().ToString("N") + ".jsonl");
        var logger = new AuditLogger(path);

        logger.Record("ssh_run", "limited", "target", "line1\r\n" + new string('x', 600), "ok");

        var entry = new AuditLogReader(path).Tail(1).Single();

        Assert.DoesNotContain("\r", entry.Action);
        Assert.DoesNotContain("\n", entry.Action);
        Assert.True(entry.Action.Length <= 503);
        Assert.EndsWith("...", entry.Action);
    }

    [Fact]
    public async Task ConcurrentLoggerWritesPreserveAllEntries()
    {
        var path = Path.Combine(Path.GetTempPath(), "llm-pw-audit-" + Guid.NewGuid().ToString("N") + ".jsonl");
        using var start = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(1, 80)
            .Select(index => Task.Run(() =>
            {
                start.Wait();
                new AuditLogger(path).Record("policy_check", "limited", $"target-{index}", $"action-{index}", "ok");
            }))
            .ToArray();

        start.Set();
        await Task.WhenAll(tasks);

        var lines = File.ReadAllLines(path);
        var entries = new AuditLogReader(path).Tail(100);

        Assert.Equal(80, lines.Length);
        Assert.Equal(80, entries.Count);
        for (var index = 1; index <= 80; index++)
        {
            Assert.Contains(entries, entry => entry.Target == $"target-{index}");
        }
    }

    [Fact]
    public void MissingAuditFileReturnsEmptyList()
    {
        var path = Path.Combine(Path.GetTempPath(), "llm-pw-audit-missing-" + Guid.NewGuid().ToString("N") + ".jsonl");

        var entries = new AuditLogReader(path).Tail(10);

        Assert.Empty(entries);
    }
}

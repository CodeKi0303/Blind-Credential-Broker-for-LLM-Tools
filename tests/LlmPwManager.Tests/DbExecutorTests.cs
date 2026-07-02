using System.Data;
using System.Data.Common;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Db;
using LlmPwManager.Routing;
using LlmPwManager.Security;
using LlmPwManager.Ssh;
using LlmPwManager.Ui;

namespace LlmPwManager.Tests;

public sealed class DbExecutorTests
{
    [Fact]
    public void ResultSanitizerRedactsSecretLikeColumns()
    {
        var result = new DbQueryResult(
            ["id", "password_hash", "apiToken", "name", "private-key"],
            [
                new Dictionary<string, object?>
                {
                    ["id"] = 1,
                    ["password_hash"] = "hash-secret",
                    ["apiToken"] = "token-secret",
                    ["name"] = "alice",
                    ["private-key"] = "key-secret"
                }
            ],
            Truncated: false,
            RedactedColumns: []);

        var sanitized = DbResultSanitizer.Sanitize(result);

        Assert.Equal(["password_hash", "apiToken", "private-key"], sanitized.RedactedColumns);
        Assert.Equal("[REDACTED]", sanitized.Rows[0]["password_hash"]);
        Assert.Equal("[REDACTED]", sanitized.Rows[0]["apiToken"]);
        Assert.Equal("[REDACTED]", sanitized.Rows[0]["private-key"]);
        Assert.Equal("alice", sanitized.Rows[0]["name"]);
        Assert.DoesNotContain("hash-secret", string.Join(" ", sanitized.Rows[0].Values));
        Assert.DoesNotContain("token-secret", string.Join(" ", sanitized.Rows[0].Values));
        Assert.DoesNotContain("key-secret", string.Join(" ", sanitized.Rows[0].Values));
    }

    [Fact]
    public void ResultSanitizerLeavesNullSecretValuesAsNull()
    {
        var result = new DbQueryResult(
            ["password"],
            [new Dictionary<string, object?> { ["password"] = null }],
            Truncated: false,
            RedactedColumns: []);

        var sanitized = DbResultSanitizer.Sanitize(result);

        Assert.Null(sanitized.Rows[0]["password"]);
        Assert.Equal(["password"], sanitized.RedactedColumns);
    }

    [Fact]
    public void ResultSanitizerRedactsSecretLikePatternsInsideStringValues()
    {
        var result = new DbQueryResult(
            ["message", "url", "count"],
            [
                new Dictionary<string, object?>
                {
                    ["message"] = "failed login token=abc123 keep=this",
                    ["url"] = "postgres://user:uri-secret@db/app",
                    ["count"] = 5
                }
            ],
            Truncated: false,
            RedactedColumns: []);

        var sanitized = DbResultSanitizer.Sanitize(result);

        Assert.Empty(sanitized.RedactedColumns);
        Assert.Equal("failed login token=[REDACTED] keep=this", sanitized.Rows[0]["message"]);
        Assert.Equal("postgres://[REDACTED]@db/app", sanitized.Rows[0]["url"]);
        Assert.Equal(5, sanitized.Rows[0]["count"]);
        Assert.DoesNotContain("abc123", string.Join(" ", sanitized.Rows[0].Values));
        Assert.DoesNotContain("uri-secret", string.Join(" ", sanitized.Rows[0].Values));
    }

    [Fact]
    public async Task ReadRowsDoesNotMarkExactMaxRowsAsTruncated()
    {
        using var reader = CreateReader(rowCount: 2);

        var result = await DbExecutor.ReadRowsAsync(reader, configuredMaxRows: 2, CancellationToken.None);

        Assert.False(result.Truncated);
        Assert.Equal(2, result.Rows.Count);
        Assert.Equal(["id", "name"], result.Columns);
    }

    [Fact]
    public async Task ReadRowsMarksTruncatedOnlyWhenAdditionalRowExists()
    {
        using var reader = CreateReader(rowCount: 3);

        var result = await DbExecutor.ReadRowsAsync(reader, configuredMaxRows: 2, CancellationToken.None);

        Assert.True(result.Truncated);
        Assert.Equal(2, result.Rows.Count);
        Assert.Equal(1, result.Rows[0]["id"]);
        Assert.Equal(2, result.Rows[1]["id"]);
    }

    [Fact]
    public async Task ReadRowsTreatsInvalidMaxRowsAsOne()
    {
        using var reader = CreateReader(rowCount: 2);

        var result = await DbExecutor.ReadRowsAsync(reader, configuredMaxRows: 0, CancellationToken.None);

        Assert.True(result.Truncated);
        Assert.Single(result.Rows);
    }

    [Fact]
    public async Task QueryWithSessionRouteRejectsMismatchedDbRouteBeforeConnecting()
    {
        var config = new AppConfig
        {
            Credentials =
            [
                new() { Alias = "db-readonly", Label = "DB readonly", UserName = "readonly" }
            ],
            DbTargets =
            [
                new()
                {
                    Id = "payments",
                    Engine = DbEngine.Postgres,
                    Host = "10.30.0.20",
                    Port = 5432,
                    Database = "payments",
                    UserName = "readonly",
                    CredentialAlias = "db-readonly",
                    RouteId = "expected-route",
                    MaxRows = 10
                }
            ]
        };
        var redactor = new SecretRedactor();
        var router = new RouteResolver(config);
        var credentials = new CredentialResolver(new FakeCredentialStore(), new FakeCredentialPrompt(), maxAttempts: 1);
        var ssh = new SshExecutor(config, router, credentials, redactor);
        var db = new DbExecutor(config, router, credentials, ssh, redactor);
        using var route = new RouteConnection("different-route", [], [], []);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            db.QueryAsync("payments", "select 1", new Dictionary<string, object?>(), route, CancellationToken.None));

        Assert.Contains("does not match", ex.Message);
    }

    private sealed class FakeCredentialStore : ICredentialStore
    {
        public bool Exists(string alias) => false;
        public string? GetSecret(string alias) => null;
        public void SaveSecret(string alias, string secret) { }
        public void DeleteSecret(string alias) { }
    }

    private sealed class FakeCredentialPrompt : ICredentialPrompt
    {
        public string? RequestPassword(string alias, string label, string userName, string reason) => null;
    }

    private static DbDataReader CreateReader(int rowCount)
    {
        var table = new DataTable();
        table.Columns.Add("id", typeof(int));
        table.Columns.Add("name", typeof(string));
        for (var i = 1; i <= rowCount; i++)
        {
            table.Rows.Add(i, "name-" + i);
        }

        return table.CreateDataReader();
    }
}

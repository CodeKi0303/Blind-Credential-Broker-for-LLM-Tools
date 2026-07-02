using System.Data.Common;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Routing;
using LlmPwManager.Security;
using LlmPwManager.Ssh;
using MySqlConnector;
using Npgsql;
using Renci.SshNet;

namespace LlmPwManager.Db;

internal sealed class DbExecutor(
    AppConfig config,
    RouteResolver router,
    CredentialResolver credentials,
    SshExecutor ssh,
    SecretRedactor redactor)
{
    public async Task<DbQueryResult> QueryAsync(
        string connectionId,
        string sql,
        IReadOnlyDictionary<string, object?> parameters,
        CancellationToken cancellationToken)
    {
        return await QueryAsync(connectionId, sql, parameters, route: null, cancellationToken);
    }

    public async Task<DbQueryResult> QueryAsync(
        string connectionId,
        string sql,
        IReadOnlyDictionary<string, object?> parameters,
        RouteConnection? route,
        CancellationToken cancellationToken)
    {
        var target = config.DbTargets.FirstOrDefault(db => db.Id.Equals(connectionId, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Unknown DB connection: {connectionId}");

        if (route is not null)
        {
            ValidateRouteMatchesTarget(target, route);
        }

        RouteConnection? ownedRoute = null;
        ForwardedPortLocal? temporaryForward = null;
        try
        {
            var activeRoute = route ?? (ownedRoute = await OpenRouteIfNeededAsync(target, cancellationToken));
            var endpoint = OpenDbEndpoint(target, activeRoute, route is not null, out temporaryForward);
            var credentialLabel = config.Credentials.FirstOrDefault(c => c.Alias == target.CredentialAlias)?.Label ?? target.CredentialAlias;
            var password = await credentials.ResolveAsync(
                target.CredentialAlias,
                credentialLabel,
                target.UserName,
                candidate => TestDbAsync(target, endpoint, candidate, cancellationToken),
                cancellationToken);

            await using var connection = CreateConnection(target, endpoint, password);
            await connection.OpenAsync(cancellationToken);

            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            BindParameters(command, parameters);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            var result = await ReadRowsAsync(reader, target.MaxRows, cancellationToken);
            return DbResultSanitizer.Sanitize(result);
        }
        finally
        {
            if (route is not null && temporaryForward is not null)
            {
                ssh.CloseForward(route, temporaryForward);
            }

            ownedRoute?.Dispose();
        }
    }

    private static void BindParameters(DbCommand command, IReadOnlyDictionary<string, object?> parameters)
    {
        foreach (var (name, value) in parameters)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new InvalidOperationException("DB parameter name cannot be empty.");
            }

            var parameter = command.CreateParameter();
            parameter.ParameterName = NormalizeParameterName(name);
            parameter.Value = value ?? DBNull.Value;
            command.Parameters.Add(parameter);
        }
    }

    internal static async Task<DbQueryResult> ReadRowsAsync(
        DbDataReader reader,
        int configuredMaxRows,
        CancellationToken cancellationToken)
    {
        var columns = Enumerable.Range(0, reader.FieldCount).Select(reader.GetName).ToList();
        var rows = new List<Dictionary<string, object?>>();
        var maxRows = Math.Max(1, configuredMaxRows);
        var truncated = false;

        while (await reader.ReadAsync(cancellationToken))
        {
            if (rows.Count >= maxRows)
            {
                truncated = true;
                break;
            }

            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var column in columns.Select((name, index) => (name, index)))
            {
                row[column.name] = await reader.IsDBNullAsync(column.index, cancellationToken)
                    ? null
                    : reader.GetValue(column.index);
            }

            rows.Add(row);
        }

        return new DbQueryResult(columns, rows, truncated, []);
    }

    private static string NormalizeParameterName(string name)
    {
        return name[0] is '@' or ':' or '?' ? name : "@" + name;
    }

    private async Task<RouteConnection?> OpenRouteIfNeededAsync(DbTarget target, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(target.RouteId))
        {
            return null;
        }

        _ = router.Resolve(target.RouteId);
        return await ssh.ConnectRouteAsync(target.RouteId, cancellationToken);
    }

    private DbEndpoint OpenDbEndpoint(
        DbTarget target,
        RouteConnection? route,
        bool closeForwardAfterQuery,
        out ForwardedPortLocal? temporaryForward)
    {
        temporaryForward = null;
        if (route is null)
        {
            return new DbEndpoint(target.Host, target.Port);
        }

        var forward = ssh.OpenForward(route, target.Host, target.Port);
        if (closeForwardAfterQuery)
        {
            temporaryForward = forward;
        }

        return new DbEndpoint("127.0.0.1", (int)forward.BoundPort);
    }

    private static void ValidateRouteMatchesTarget(DbTarget target, RouteConnection route)
    {
        if (string.IsNullOrWhiteSpace(target.RouteId))
        {
            throw new InvalidOperationException("DB connection is not configured for SSH routing.");
        }

        if (!target.RouteId.Equals(route.RouteId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("SSH session route does not match DB connection route.");
        }
    }

    private async Task<CredentialTestResult> TestDbAsync(DbTarget target, DbEndpoint endpoint, string password, CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = CreateConnection(target, endpoint, password);
            await connection.OpenAsync(cancellationToken);
            return new CredentialTestResult(true);
        }
        catch (Exception ex) when (IsAuthenticationOrConnectionFailure(ex))
        {
            return new CredentialTestResult(false, redactor.Redact(ex.Message, [password]));
        }
    }

    private static DbConnection CreateConnection(DbTarget target, DbEndpoint endpoint, string password)
    {
        return target.Engine switch
        {
            DbEngine.Postgres => new NpgsqlConnection(BuildPostgresConnectionString(target, endpoint, password)),
            DbEngine.MySql => new MySqlConnection(BuildMySqlConnectionString(target, endpoint, password)),
            _ => throw new NotSupportedException($"Unsupported DB engine: {target.Engine}")
        };
    }

    private static string BuildPostgresConnectionString(DbTarget target, DbEndpoint endpoint, string password)
    {
        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = endpoint.Host,
            Port = endpoint.Port,
            Database = target.Database,
            Username = target.UserName,
            Password = password,
            Timeout = 20,
            CommandTimeout = 60
        };
        return builder.ConnectionString;
    }

    private static string BuildMySqlConnectionString(DbTarget target, DbEndpoint endpoint, string password)
    {
        var builder = new MySqlConnectionStringBuilder
        {
            Server = endpoint.Host,
            Port = (uint)endpoint.Port,
            Database = target.Database,
            UserID = target.UserName,
            Password = password,
            ConnectionTimeout = 20,
            DefaultCommandTimeout = 60
        };
        return builder.ConnectionString;
    }

    private static bool IsAuthenticationOrConnectionFailure(Exception ex)
    {
        return ex is DbException or TimeoutException or MySqlException or NpgsqlException;
    }
}

internal sealed record DbEndpoint(string Host, int Port);

internal sealed record DbQueryResult(
    IReadOnlyList<string> Columns,
    IReadOnlyList<Dictionary<string, object?>> Rows,
    bool Truncated,
    IReadOnlyList<string> RedactedColumns);

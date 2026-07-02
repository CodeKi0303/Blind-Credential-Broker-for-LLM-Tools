namespace LlmPwManager.Ssh;

internal sealed class SshSessionManager : IDisposable
{
    private readonly Func<string, CancellationToken, Task<RouteConnection>> connectRoute;
    private readonly Func<RouteConnection, string, CancellationToken, Task<SshRunResult>> runCommand;
    private readonly TimeSpan idleTimeout;
    private readonly Func<DateTimeOffset> now;
    private readonly object sync = new();
    private readonly Dictionary<string, SshSession> sessions = new(StringComparer.OrdinalIgnoreCase);

    public SshSessionManager(SshExecutor ssh, TimeSpan idleTimeout)
        : this(ssh.ConnectRouteAsync, ssh.RunCommandAsync, idleTimeout, () => DateTimeOffset.UtcNow)
    {
    }

    internal SshSessionManager(
        Func<string, CancellationToken, Task<RouteConnection>> connectRoute,
        Func<RouteConnection, string, CancellationToken, Task<SshRunResult>> runCommand,
        TimeSpan idleTimeout,
        Func<DateTimeOffset> now)
    {
        this.connectRoute = connectRoute;
        this.runCommand = runCommand;
        this.idleTimeout = idleTimeout <= TimeSpan.Zero ? TimeSpan.FromMinutes(30) : idleTimeout;
        this.now = now;
    }

    public async Task<SshSessionInfo> OpenAsync(string routeId, string clientProfile, string purpose, CancellationToken cancellationToken)
    {
        var connection = await connectRoute(routeId, cancellationToken);
        DisposeAll(PurgeExpired());
        var currentTime = now();
        var session = new SshSession(
            "ssh_" + Guid.NewGuid().ToString("N"),
            routeId,
            clientProfile,
            purpose,
            currentTime,
            connection);

        lock (sync)
        {
            sessions.Add(session.Id, session);
        }

        return session.ToInfo(idleTimeout);
    }

    public IReadOnlyList<SshSessionInfo> List(string clientProfile)
    {
        DisposeAll(PurgeExpired());
        lock (sync)
        {
            return sessions.Values
                .Where(session => session.ClientProfile.Equals(clientProfile, StringComparison.OrdinalIgnoreCase))
                .OrderBy(session => session.CreatedAt)
                .Select(session => session.ToInfo(idleTimeout))
                .ToList();
        }
    }

    public bool TryGetInfo(string sessionId, string clientProfile, out SshSessionInfo info)
    {
        DisposeAll(PurgeExpired());
        lock (sync)
        {
            if (sessions.TryGetValue(sessionId, out var session) &&
                session.ClientProfile.Equals(clientProfile, StringComparison.OrdinalIgnoreCase))
            {
                info = session.ToInfo(idleTimeout);
                return true;
            }
        }

        info = default!;
        return false;
    }

    public async Task<SshRunResult> RunCommandAsync(string sessionId, string clientProfile, string command, CancellationToken cancellationToken)
    {
        return await UseConnectionAsync(
            sessionId,
            clientProfile,
            (connection, token) => runCommand(connection, command, token),
            cancellationToken);
    }

    public async Task<T> UseConnectionAsync<T>(
        string sessionId,
        string clientProfile,
        Func<RouteConnection, CancellationToken, Task<T>> useConnection,
        CancellationToken cancellationToken)
    {
        SshSession session;
        lock (sync)
        {
            if (!sessions.TryGetValue(sessionId, out session!))
            {
                throw new InvalidOperationException("SSH session was not found.");
            }

            if (!session.ClientProfile.Equals(clientProfile, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("SSH session was not found.");
            }

            if (IsExpired(session.LastUsedAt, now(), idleTimeout))
            {
                sessions.Remove(sessionId);
                session.Dispose();
                throw new InvalidOperationException("SSH session expired.");
            }

            session.Retain();
        }

        var gateEntered = false;
        try
        {
            await session.Gate.WaitAsync(cancellationToken);
            gateEntered = true;
            session.Touch(now());
            return await useConnection(session.Connection, cancellationToken);
        }
        finally
        {
            if (gateEntered)
            {
                session.Gate.Release();
            }

            lock (sync)
            {
                session.Release();
            }
        }
    }

    public bool Close(string sessionId, string clientProfile)
    {
        SshSession? session;
        lock (sync)
        {
            if (!sessions.TryGetValue(sessionId, out session) ||
                !session.ClientProfile.Equals(clientProfile, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            sessions.Remove(sessionId);
        }

        session.Dispose();
        return true;
    }

    public void Dispose()
    {
        List<SshSession> snapshot;
        lock (sync)
        {
            snapshot = sessions.Values.ToList();
            sessions.Clear();
        }

        foreach (var session in snapshot)
        {
            session.Dispose();
        }
    }

    internal static bool IsExpired(DateTimeOffset lastUsedAt, DateTimeOffset currentTime, TimeSpan idleTimeout)
    {
        return currentTime - lastUsedAt >= idleTimeout;
    }

    private List<SshSession> PurgeExpired()
    {
        var currentTime = now();
        lock (sync)
        {
            var expired = sessions.Values
                .Where(session => session.InUseCount == 0 && IsExpired(session.LastUsedAt, currentTime, idleTimeout))
                .ToList();
            foreach (var session in expired)
            {
                sessions.Remove(session.Id);
            }

            return expired;
        }
    }

    private static void DisposeAll(IEnumerable<SshSession> expired)
    {
        foreach (var session in expired)
        {
            session.Dispose();
        }
    }

    private sealed class SshSession(
        string id,
        string routeId,
        string clientProfile,
        string purpose,
        DateTimeOffset createdAt,
        RouteConnection connection) : IDisposable
    {
        public string Id { get; } = id;
        public string RouteId { get; } = routeId;
        public string ClientProfile { get; } = clientProfile;
        public string Purpose { get; } = purpose;
        public DateTimeOffset CreatedAt { get; } = createdAt;
        public DateTimeOffset LastUsedAt { get; private set; } = createdAt;
        public RouteConnection Connection { get; } = connection;
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public int InUseCount { get; private set; }

        public void Retain()
        {
            InUseCount++;
        }

        public void Release()
        {
            InUseCount = Math.Max(0, InUseCount - 1);
        }

        public void Touch(DateTimeOffset currentTime)
        {
            LastUsedAt = currentTime;
        }

        public SshSessionInfo ToInfo(TimeSpan idleTimeout) => new(
            Id,
            RouteId,
            ClientProfile,
            Purpose,
            CreatedAt,
            LastUsedAt,
            LastUsedAt + idleTimeout);

        public void Dispose()
        {
            Gate.Dispose();
            Connection.Dispose();
        }
    }
}

internal sealed record SshSessionInfo(
    string SessionId,
    string RouteId,
    string ClientProfile,
    string Purpose,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastUsedAt,
    DateTimeOffset ExpiresAt);

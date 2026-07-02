using LlmPwManager.Ssh;

namespace LlmPwManager.Tests;

public sealed class SshSessionManagerTests
{
    [Fact]
    public void IsExpiredUsesIdleTimeoutBoundary()
    {
        var lastUsed = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        Assert.False(SshSessionManager.IsExpired(lastUsed, lastUsed.AddMinutes(29), TimeSpan.FromMinutes(30)));
        Assert.True(SshSessionManager.IsExpired(lastUsed, lastUsed.AddMinutes(30), TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public async Task SessionsAreListedOnlyForOwningProfile()
    {
        var currentTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using var manager = CreateManager(() => currentTime);

        var fullSession = await manager.OpenAsync("prod", "full", "admin work", CancellationToken.None);
        var limitedSession = await manager.OpenAsync("prod", "limited", "read work", CancellationToken.None);

        var fullSessions = manager.List("full");
        var limitedSessions = manager.List("limited");

        Assert.Single(fullSessions);
        Assert.Single(limitedSessions);
        Assert.Equal(fullSession.SessionId, fullSessions[0].SessionId);
        Assert.Equal("full", fullSessions[0].ClientProfile);
        Assert.Equal(limitedSession.SessionId, limitedSessions[0].SessionId);
        Assert.Equal("limited", limitedSessions[0].ClientProfile);
    }

    [Fact]
    public async Task SessionLookupCloseAndUseRequireOwningProfile()
    {
        var currentTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var runCalls = 0;
        using var manager = CreateManager(
            () => currentTime,
            (_, _, _) =>
            {
                runCalls++;
                return Task.FromResult(new SshRunResult(0, "ok", ""));
            });

        var session = await manager.OpenAsync("prod", "full", "admin work", CancellationToken.None);

        Assert.False(manager.TryGetInfo(session.SessionId, "limited", out _));
        Assert.False(manager.Close(session.SessionId, "limited"));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            manager.RunCommandAsync(session.SessionId, "limited", "uptime", CancellationToken.None));
        Assert.Equal(0, runCalls);

        Assert.True(manager.TryGetInfo(session.SessionId, "full", out var info));
        Assert.Equal(session.SessionId, info.SessionId);
        var result = await manager.RunCommandAsync(session.SessionId, "full", "uptime", CancellationToken.None);
        Assert.Equal("ok", result.Stdout);
        Assert.Equal(1, runCalls);
        Assert.True(manager.Close(session.SessionId, "full"));
    }

    private static SshSessionManager CreateManager(
        Func<DateTimeOffset> now,
        Func<RouteConnection, string, CancellationToken, Task<SshRunResult>>? runCommand = null)
    {
        return new SshSessionManager(
            (routeId, _) => Task.FromResult(new RouteConnection(routeId, [], [], [])),
            runCommand ?? ((_, _, _) => Task.FromResult(new SshRunResult(0, "", ""))),
            TimeSpan.FromMinutes(30),
            now);
    }
}

using System.Net;
using System.Net.Sockets;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Routing;
using LlmPwManager.Security;
using Renci.SshNet;

namespace LlmPwManager.Ssh;

internal sealed class SshExecutor(
    AppConfig config,
    RouteResolver router,
    CredentialResolver credentials,
    SecretRedactor redactor)
{
    public async Task<SshRunResult> RunCommandAsync(string routeId, string command, CancellationToken cancellationToken)
    {
        using var connection = await ConnectRouteAsync(routeId, cancellationToken);
        return await RunCommandAsync(connection, command, cancellationToken);
    }

    public Task<SshRunResult> RunCommandAsync(RouteConnection connection, string command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var cmd = connection.LeafClient.RunCommand(command);
        return Task.FromResult(new SshRunResult(
            cmd.ExitStatus ?? -1,
            redactor.Redact(cmd.Result, connection.Secrets),
            redactor.Redact(cmd.Error, connection.Secrets)));
    }

    public async Task<SshRunResult> RunSudoCommandAsync(
        string routeId,
        string command,
        string sudoUser,
        string credentialAlias,
        CancellationToken cancellationToken)
    {
        using var connection = await ConnectRouteAsync(routeId, cancellationToken);
        return await RunSudoCommandAsync(connection, command, sudoUser, credentialAlias, cancellationToken);
    }

    public async Task<SshRunResult> RunSudoCommandAsync(
        RouteConnection connection,
        string command,
        string sudoUser,
        string credentialAlias,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsSafeSudoUser(sudoUser))
        {
            throw new InvalidOperationException("Invalid sudo user.");
        }

        var sudoLabel = $"sudo password for {credentialAlias}";
        if (await TestSudoAsync(connection, sudoUser, password: null, cancellationToken))
        {
            return await ExecuteSudoAsync(connection, command, sudoUser, password: null, cancellationToken);
        }

        var sudoSecret = await credentials.ResolveAsync(
            credentialAlias,
            sudoLabel,
            sudoUser,
            candidate => TestSudoPasswordAsync(connection, sudoUser, candidate, cancellationToken),
            cancellationToken);

        return await ExecuteSudoAsync(connection, command, sudoUser, sudoSecret, cancellationToken);
    }

    public async Task<RouteConnection> ConnectRouteAsync(string routeId, CancellationToken cancellationToken)
    {
        var route = router.Resolve(routeId);
        var clients = new List<SshClient>();
        var forwards = new List<ForwardedPortLocal>();
        var secrets = new List<string>();

        try
        {
            foreach (var target in route.SshChain)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var endpoint = BuildEndpoint(target, clients.LastOrDefault(), forwards);
                var secret = await ResolveAuthSecretAsync(target, endpoint, cancellationToken);

                var client = CreateClient(endpoint.Host, endpoint.Port, target, secret);
                client.Connect();
                clients.Add(client);
                if (!string.IsNullOrEmpty(secret))
                {
                    secrets.Add(secret);
                }
            }

            return new RouteConnection(route.Id, clients, forwards, secrets);
        }
        catch
        {
            foreach (var forward in forwards)
            {
                forward.Dispose();
            }

            foreach (var client in clients)
            {
                client.Dispose();
            }

            throw;
        }
    }

    public ForwardedPortLocal OpenForward(RouteConnection route, string host, int port)
    {
        var localPort = PortAllocator.GetFreeTcpPort();
        var forward = new ForwardedPortLocal(IPAddress.Loopback.ToString(), (uint)localPort, host, (uint)port);
        route.LeafClient.AddForwardedPort(forward);
        forward.Start();
        route.AddForward(forward);
        return forward;
    }

    public void CloseForward(RouteConnection route, ForwardedPortLocal forward)
    {
        route.RemoveForward(forward);
        try
        {
            if (forward.IsStarted)
            {
                forward.Stop();
            }
        }
        finally
        {
            forward.Dispose();
        }
    }

    private async Task<CredentialTestResult> TestSudoPasswordAsync(
        RouteConnection connection,
        string sudoUser,
        string password,
        CancellationToken cancellationToken)
    {
        return await TestSudoAsync(connection, sudoUser, password, cancellationToken)
            ? new CredentialTestResult(true)
            : new CredentialTestResult(false, "sudo authentication failed.");
    }

    private static async Task<bool> TestSudoAsync(
        RouteConnection connection,
        string sudoUser,
        string? password,
        CancellationToken cancellationToken)
    {
        var sudoCommand = password is null
            ? $"sudo -n -u {sudoUser} -v"
            : $"sudo -S -p \"\" -u {sudoUser} -v";
        var result = await ExecuteCommandWithOptionalInputAsync(connection.LeafClient, sudoCommand, password, cancellationToken);
        return result.ExitStatus == 0;
    }

    private async Task<SshRunResult> ExecuteSudoAsync(
        RouteConnection connection,
        string command,
        string sudoUser,
        string? password,
        CancellationToken cancellationToken)
    {
        var sudoCommand = password is null
            ? $"sudo -n -u {sudoUser} -- sh -lc {QuoteShellArgument(command)}"
            : $"sudo -S -p \"\" -u {sudoUser} -- sh -lc {QuoteShellArgument(command)}";
        var result = await ExecuteCommandWithOptionalInputAsync(connection.LeafClient, sudoCommand, password, cancellationToken);
        var secrets = string.IsNullOrEmpty(password)
            ? connection.Secrets
            : connection.Secrets.Concat([password]).ToList();
        return new SshRunResult(
            result.ExitStatus,
            redactor.Redact(result.Stdout, secrets),
            redactor.Redact(result.Stderr, secrets));
    }

    private static async Task<SshRunResult> ExecuteCommandWithOptionalInputAsync(
        SshClient client,
        string commandText,
        string? inputLine,
        CancellationToken cancellationToken)
    {
        using var command = client.CreateCommand(commandText);
        var executeTask = command.ExecuteAsync(cancellationToken);
        if (inputLine is not null)
        {
            await using var input = command.CreateInputStream();
            var payload = System.Text.Encoding.UTF8.GetBytes(inputLine + "\n");
            await input.WriteAsync(payload, cancellationToken);
        }

        await executeTask;
        return new SshRunResult(command.ExitStatus ?? -1, command.Result, command.Error);
    }

    private static string QuoteShellArgument(string value)
    {
        return "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";
    }

    private static bool IsSafeSudoUser(string sudoUser)
    {
        if (string.IsNullOrWhiteSpace(sudoUser))
        {
            return false;
        }

        return sudoUser.All(ch => char.IsLetterOrDigit(ch) || ch is '_' or '-' or '.');
    }

    private SshEndpoint BuildEndpoint(SshTarget target, SshClient? previousClient, List<ForwardedPortLocal> forwards)
    {
        if (previousClient is null)
        {
            return new SshEndpoint(target.Host, target.Port);
        }

        var localPort = PortAllocator.GetFreeTcpPort();
        var forward = new ForwardedPortLocal(IPAddress.Loopback.ToString(), (uint)localPort, target.Host, (uint)target.Port);
        previousClient.AddForwardedPort(forward);
        forward.Start();
        forwards.Add(forward);
        return new SshEndpoint(IPAddress.Loopback.ToString(), localPort);
    }

    private Task<string?> ResolveAuthSecretAsync(SshTarget target, SshEndpoint endpoint, CancellationToken cancellationToken)
    {
        if (target.AuthMode == SshAuthMode.PrivateKey && string.IsNullOrWhiteSpace(target.CredentialAlias))
        {
            return Task.FromResult<string?>(null);
        }

        var credentialLabel = config.Credentials.FirstOrDefault(c => c.Alias == target.CredentialAlias)?.Label ?? target.CredentialAlias;
        var label = target.AuthMode == SshAuthMode.PrivateKey
            ? $"{credentialLabel} (private key passphrase)"
            : credentialLabel;

        return ResolveRequiredSecretAsync(target, endpoint, label, cancellationToken);
    }

    private async Task<string?> ResolveRequiredSecretAsync(SshTarget target, SshEndpoint endpoint, string label, CancellationToken cancellationToken)
    {
        return await credentials.ResolveAsync(
            target.CredentialAlias,
            label,
            target.UserName,
            candidate => TestSshAsync(endpoint, target, candidate),
            cancellationToken);
    }

    private static Task<CredentialTestResult> TestSshAsync(SshEndpoint endpoint, SshTarget target, string secret)
    {
        return Task.Run(() =>
        {
            try
            {
                using var client = CreateClient(endpoint.Host, endpoint.Port, target, secret);
                client.Connect();
                client.Disconnect();
                return new CredentialTestResult(true);
            }
            catch
            {
                return new CredentialTestResult(false, "SSH authentication failed.");
            }
        });
    }

    private static SshClient CreateClient(string host, int port, SshTarget target, string? secret)
    {
        var auth = CreateAuthMethod(target, secret);
        var connectionInfo = new ConnectionInfo(host, port, target.UserName, auth)
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
        return new SshClient(connectionInfo);
    }

    private static AuthenticationMethod CreateAuthMethod(SshTarget target, string? secret)
    {
        return target.AuthMode switch
        {
            SshAuthMode.Password => new PasswordAuthenticationMethod(target.UserName, secret ?? ""),
            SshAuthMode.PrivateKey => CreatePrivateKeyAuth(target, secret),
            _ => throw new NotSupportedException($"Unsupported SSH auth mode: {target.AuthMode}")
        };
    }

    private static PrivateKeyAuthenticationMethod CreatePrivateKeyAuth(SshTarget target, string? passphrase)
    {
        if (string.IsNullOrWhiteSpace(target.PrivateKeyPath))
        {
            throw new InvalidOperationException($"SSH target {target.Id} uses private key auth but privateKeyPath is empty.");
        }

        var expandedPath = Environment.ExpandEnvironmentVariables(target.PrivateKeyPath);
        var keyFile = string.IsNullOrEmpty(passphrase)
            ? new PrivateKeyFile(expandedPath)
            : new PrivateKeyFile(expandedPath, passphrase);
        return new PrivateKeyAuthenticationMethod(target.UserName, keyFile);
    }
}

internal sealed record SshEndpoint(string Host, int Port);

internal sealed record SshRunResult(int ExitStatus, string Stdout, string Stderr);

internal sealed class RouteConnection(
    string routeId,
    List<SshClient> clients,
    List<ForwardedPortLocal> forwards,
    List<string> secrets) : IDisposable
{
    public string RouteId { get; } = routeId;
    public SshClient LeafClient => clients.Last();
    public IReadOnlyList<string> Secrets => secrets;

    public void AddForward(ForwardedPortLocal forward) => forwards.Add(forward);

    public void RemoveForward(ForwardedPortLocal forward) => forwards.Remove(forward);

    public void Dispose()
    {
        foreach (var forward in forwards.AsEnumerable().Reverse())
        {
            try
            {
                if (forward.IsStarted)
                {
                    forward.Stop();
                }
            }
            finally
            {
                forward.Dispose();
            }
        }

        foreach (var client in clients.AsEnumerable().Reverse())
        {
            try
            {
                if (client.IsConnected)
                {
                    client.Disconnect();
                }
            }
            finally
            {
                client.Dispose();
            }
        }
    }
}

internal static class PortAllocator
{
    public static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

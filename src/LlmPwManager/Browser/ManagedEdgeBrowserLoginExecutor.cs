using System.Diagnostics;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Ssh;

namespace LlmPwManager.Browser;

internal sealed class ManagedEdgeBrowserLoginExecutor(
    AppConfig config,
    CredentialResolver credentials,
    string appDirectory) : IBrowserLoginExecutor
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<BrowserLoginResult> LoginAsync(BrowserTarget target, CancellationToken cancellationToken)
    {
        if (target.IsolationMode == BrowserIsolationMode.Disabled)
        {
            return new BrowserLoginResult(false, "browser_adapter_disabled", "Browser target is disabled.");
        }

        if (target.IsolationMode != BrowserIsolationMode.ManagedProfile)
        {
            return new BrowserLoginResult(false, "browser_adapter_unsupported", "Browser isolation mode is not supported yet.");
        }

        var credentialLabel = config.Credentials.FirstOrDefault(c => c.Alias == target.CredentialAlias)?.Label ?? target.CredentialAlias;
        await credentials.ResolveAsync(
            target.CredentialAlias,
            credentialLabel,
            target.UserName,
            candidate => TestLoginAsync(target, candidate, cancellationToken),
            cancellationToken);

        return new BrowserLoginResult(true, "login_verified");
    }

    private async Task<CredentialTestResult> TestLoginAsync(BrowserTarget target, string password, CancellationToken cancellationToken)
    {
        var edgePath = EdgeLocator.FindExecutable();
        if (edgePath is null)
        {
            return new CredentialTestResult(false, "Microsoft Edge executable was not found.");
        }

        var port = PortAllocator.GetFreeTcpPort();
        var profileDirectory = Path.Combine(
            appDirectory,
            "browser-profiles",
            SanitizePathSegment(target.Id),
            "run-" + DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmssfff") + "-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(profileDirectory);

        using var process = StartEdge(edgePath, profileDirectory, port, target.LoginUrl);
        try
        {
            await using var cdp = await EdgeCdpSession.ConnectAsync(port, cancellationToken);

            var loaded = await cdp.EvaluateStringAsync(BuildFillScript(target, password), cancellationToken);
            if (!loaded.Equals("filled", StringComparison.OrdinalIgnoreCase))
            {
                await ClearPasswordFieldAsync(cdp, target, cancellationToken);
                return new CredentialTestResult(false, loaded);
            }

            var result = await cdp.EvaluateStringAsync(BuildResultScript(target), cancellationToken);
            if (result.Equals("success", StringComparison.OrdinalIgnoreCase))
            {
                return new CredentialTestResult(true);
            }

            await ClearPasswordFieldAsync(cdp, target, cancellationToken);
            return new CredentialTestResult(false, result);
        }
        finally
        {
            await StopEdgeAsync(process, CancellationToken.None);
            DeleteDirectoryBestEffort(profileDirectory);
        }
    }

    private static Process StartEdge(string edgePath, string profileDirectory, int port, string loginUrl)
    {
        var start = new ProcessStartInfo(edgePath)
        {
            UseShellExecute = false
        };
        start.ArgumentList.Add($"--remote-debugging-port={port}");
        start.ArgumentList.Add("--remote-allow-origins=*");
        start.ArgumentList.Add("--no-first-run");
        start.ArgumentList.Add("--no-default-browser-check");
        start.ArgumentList.Add($"--user-data-dir={profileDirectory}");
        start.ArgumentList.Add(loginUrl);

        return Process.Start(start) ?? throw new InvalidOperationException("Could not start Microsoft Edge.");
    }

    private static async Task StopEdgeAsync(Process process, CancellationToken cancellationToken)
    {
        try
        {
            if (process.HasExited)
            {
                return;
            }

            process.CloseMainWindow();
            var exited = await Task.Run(() => process.WaitForExit(3000), cancellationToken);
            if (!exited && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(cancellationToken);
            }
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Best-effort cleanup. Login result and credential storage are decided before this point.
        }
    }

    internal static void DeleteDirectoryBestEffort(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch
        {
            // Browser cleanup is best-effort because Edge may still be releasing files.
        }
    }

    private static async Task ClearPasswordFieldAsync(EdgeCdpSession cdp, BrowserTarget target, CancellationToken cancellationToken)
    {
        try
        {
            await cdp.EvaluateStringAsync(BuildClearPasswordScript(target), cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Best-effort cleanup. The original login result remains the actionable signal.
        }
    }

    internal static string BuildFillScript(BrowserTarget target, string password)
    {
        var timeoutMs = target.LoginTimeoutSeconds * 1000;
        return $$"""
            (async () => {
              const userSelector = {{JsString(target.UserNameSelector)}};
              const passwordSelector = {{JsString(target.PasswordSelector)}};
              const submitSelector = {{JsString(target.SubmitSelector)}};
              const userName = {{JsString(target.UserName)}};
              const password = {{JsString(password)}};
              const deadline = Date.now() + {{timeoutMs}};
              const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
              while (Date.now() < deadline) {
                const user = document.querySelector(userSelector);
                const pass = document.querySelector(passwordSelector);
                const submit = document.querySelector(submitSelector);
                if (user && pass && submit) {
                  user.focus();
                  user.value = userName;
                  user.dispatchEvent(new Event('input', { bubbles: true }));
                  user.dispatchEvent(new Event('change', { bubbles: true }));
                  pass.focus();
                  pass.value = password;
                  pass.dispatchEvent(new Event('input', { bubbles: true }));
                  pass.dispatchEvent(new Event('change', { bubbles: true }));
                  submit.click();
                  return 'filled';
                }
                await sleep(250);
              }
              return 'login_fields_not_found';
            })()
            """;
    }

    internal static string BuildResultScript(BrowserTarget target)
    {
        var timeoutMs = target.LoginTimeoutSeconds * 1000;
        return $$"""
            (async () => {
              const successSelector = {{JsString(target.SuccessSelector ?? "")}};
              const successUrlContains = {{JsString(target.SuccessUrlContains ?? "")}};
              const failureSelector = {{JsString(target.FailureSelector ?? "")}};
              const deadline = Date.now() + {{timeoutMs}};
              const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
              while (Date.now() < deadline) {
                if (failureSelector && document.querySelector(failureSelector)) {
                  return 'login_failed';
                }
                if (successSelector && document.querySelector(successSelector)) {
                  return 'success';
                }
                if (successUrlContains && location.href.includes(successUrlContains)) {
                  return 'success';
                }
                await sleep(250);
              }
              return 'login_success_not_observed';
            })()
            """;
    }

    internal static string BuildClearPasswordScript(BrowserTarget target)
    {
        return $$"""
            (() => {
              const passwordSelector = {{JsString(target.PasswordSelector)}};
              const pass = document.querySelector(passwordSelector);
              if (!pass) {
                return 'password_field_not_found';
              }
              pass.value = '';
              pass.dispatchEvent(new Event('input', { bubbles: true }));
              pass.dispatchEvent(new Event('change', { bubbles: true }));
              pass.blur();
              return 'password_cleared';
            })()
            """;
    }

    private static string JsString(string value) => JsonSerializer.Serialize(value, JsonOptions);

    private static string SanitizePathSegment(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var chars = value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray();
        var sanitized = new string(chars).Trim();
        return string.IsNullOrWhiteSpace(sanitized) ? "browser" : sanitized;
    }

    private sealed class EdgeCdpSession(ClientWebSocket socket) : IAsyncDisposable
    {
        private int nextId;

        public static async Task<EdgeCdpSession> ConnectAsync(int port, CancellationToken cancellationToken)
        {
            using var http = new HttpClient();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
            string? webSocketUrl = null;
            while (DateTimeOffset.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    using var document = JsonDocument.Parse(await http.GetStringAsync($"http://127.0.0.1:{port}/json/list", cancellationToken));
                    webSocketUrl = document.RootElement.EnumerateArray()
                        .Where(page => page.TryGetProperty("type", out var type) && type.GetString() == "page")
                        .Select(page => page.GetProperty("webSocketDebuggerUrl").GetString())
                        .FirstOrDefault(url => !string.IsNullOrWhiteSpace(url));
                    if (webSocketUrl is not null)
                    {
                        break;
                    }
                }
                catch (HttpRequestException)
                {
                    await Task.Delay(250, cancellationToken);
                }
            }

            if (webSocketUrl is null)
            {
                throw new InvalidOperationException("Could not connect to Microsoft Edge DevTools endpoint.");
            }

            var socket = new ClientWebSocket();
            await socket.ConnectAsync(new Uri(webSocketUrl), cancellationToken);
            var session = new EdgeCdpSession(socket);
            await session.CallAsync("Runtime.enable", null, cancellationToken);
            return session;
        }

        public async Task<string> EvaluateStringAsync(string expression, CancellationToken cancellationToken)
        {
            using var response = await CallAsync(
                "Runtime.evaluate",
                new
                {
                    expression,
                    awaitPromise = true,
                    returnByValue = true
                },
                cancellationToken);

            if (response.RootElement.TryGetProperty("error", out _))
            {
                return "browser_script_error";
            }

            if (response.RootElement.TryGetProperty("result", out var result) &&
                result.TryGetProperty("exceptionDetails", out _))
            {
                return "browser_script_exception";
            }

            return response.RootElement
                       .GetProperty("result")
                       .GetProperty("result")
                       .GetProperty("value")
                       .GetString() ??
                   "browser_script_empty_result";
        }

        private async Task<JsonDocument> CallAsync(string method, object? parameters, CancellationToken cancellationToken)
        {
            var id = Interlocked.Increment(ref nextId);
            var request = parameters is null
                ? JsonSerializer.Serialize(new { id, method }, JsonOptions)
                : JsonSerializer.Serialize(new { id, method, @params = parameters }, JsonOptions);
            var requestBytes = Encoding.UTF8.GetBytes(request);
            await socket.SendAsync(requestBytes, WebSocketMessageType.Text, true, cancellationToken);

            while (true)
            {
                var response = await ReceiveJsonAsync(cancellationToken);
                if (response.RootElement.TryGetProperty("id", out var responseId) &&
                    responseId.ValueKind == JsonValueKind.Number &&
                    responseId.GetInt32() == id)
                {
                    return response;
                }

                response.Dispose();
            }
        }

        private async Task<JsonDocument> ReceiveJsonAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[16 * 1024];
            using var stream = new MemoryStream();
            WebSocketReceiveResult result;
            do
            {
                result = await socket.ReceiveAsync(buffer, cancellationToken);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    throw new InvalidOperationException("Microsoft Edge DevTools socket closed.");
                }

                stream.Write(buffer, 0, result.Count);
            }
            while (!result.EndOfMessage);

            stream.Position = 0;
            return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (socket.State == WebSocketState.Open)
                {
                    await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None);
                }
            }
            finally
            {
                socket.Dispose();
            }
        }
    }
}

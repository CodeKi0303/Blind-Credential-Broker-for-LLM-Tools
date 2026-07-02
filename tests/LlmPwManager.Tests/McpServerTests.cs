using System.Text;
using System.Text.Json;
using LlmPwManager.Audit;
using LlmPwManager.Config;
using LlmPwManager.Credentials;
using LlmPwManager.Mcp;
using LlmPwManager.Policy;
using LlmPwManager.Ui;

namespace LlmPwManager.Tests;

public sealed class McpServerTests
{
    [Fact]
    public async Task UnknownMethodDoesNotEchoMethodText()
    {
        var response = await SendAsync("""
            {"jsonrpc":"2.0","id":1,"method":"Password=super-secret"}
            """);

        Assert.Equal(-32601, response.GetProperty("error").GetProperty("code").GetInt32());
        Assert.Equal("Method not found.", response.GetProperty("error").GetProperty("message").GetString());
        Assert.DoesNotContain("super-secret", response.GetRawText());
    }

    [Fact]
    public async Task MissingMethodReturnsInvalidRequest()
    {
        var response = await SendAsync("""
            {"jsonrpc":"2.0","id":"abc"}
            """);

        Assert.Equal("abc", response.GetProperty("id").GetString());
        Assert.Equal(-32600, response.GetProperty("error").GetProperty("code").GetInt32());
        Assert.Equal("Invalid request.", response.GetProperty("error").GetProperty("message").GetString());
    }

    [Fact]
    public async Task MalformedJsonReturnsParseError()
    {
        var input = new MemoryStream(Frame("{"));
        var output = new MemoryStream();
        var server = new McpServer(null!);

        await server.RunAsync(input, output, CancellationToken.None);

        var response = ReadResponse(output);
        Assert.Equal(-32700, response.GetProperty("error").GetProperty("code").GetInt32());
        Assert.Equal("Parse error.", response.GetProperty("error").GetProperty("message").GetString());
        Assert.Equal(JsonValueKind.Null, response.GetProperty("id").ValueKind);
    }

    [Fact]
    public async Task ToolListInternalExceptionReturnsGenericJsonRpcError()
    {
        var response = await SendAsync("""
            {"jsonrpc":"2.0","id":3,"method":"tools/list"}
            """);

        Assert.Equal(3, response.GetProperty("id").GetInt32());
        Assert.Equal(-32603, response.GetProperty("error").GetProperty("code").GetInt32());
        Assert.Equal("Internal error.", response.GetProperty("error").GetProperty("message").GetString());
    }

    [Fact]
    public async Task UnknownToolCallDoesNotEchoRequestedToolName()
    {
        var response = await SendAsync("""
            {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"Password=super-secret","arguments":{}}}
            """, CreateRegistry());

        var text = response.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString() ?? "";
        Assert.Contains("unknown_tool", text);
        Assert.DoesNotContain("super-secret", response.GetRawText());
    }

    [Fact]
    public async Task ToolCallWithInvalidParamsReturnsSafeToolError()
    {
        var response = await SendAsync("""
            {"jsonrpc":"2.0","id":5,"method":"tools/call","params":"Password=super-secret"}
            """, CreateRegistry());

        var text = response.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString() ?? "";

        Assert.Contains("invalid_request", text);
        Assert.DoesNotContain("super-secret", response.GetRawText());
    }

    [Fact]
    public async Task ToolCallWithNonObjectArgumentsReturnsSafeToolError()
    {
        var response = await SendAsync("""
            {"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"credential_status","arguments":"Password=super-secret"}}
            """, CreateRegistry());

        var text = response.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString() ?? "";

        Assert.Contains("invalid_request", text);
        Assert.DoesNotContain("super-secret", response.GetRawText());
    }

    private static async Task<JsonElement> SendAsync(string json, ToolRegistry? tools = null)
    {
        var input = new MemoryStream(Frame(json));
        var output = new MemoryStream();
        var server = new McpServer(tools!);

        await server.RunAsync(input, output, CancellationToken.None);

        return ReadResponse(output);
    }

    private static byte[] Frame(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        var header = Encoding.ASCII.GetBytes($"Content-Length: {payload.Length}\r\n\r\n");
        return header.Concat(payload).ToArray();
    }

    private static JsonElement ReadResponse(MemoryStream output)
    {
        var bytes = output.ToArray();
        var marker = Encoding.ASCII.GetBytes("\r\n\r\n");
        var bodyStart = -1;
        for (var i = 0; i <= bytes.Length - marker.Length; i++)
        {
            if (bytes.AsSpan(i, marker.Length).SequenceEqual(marker))
            {
                bodyStart = i + marker.Length;
                break;
            }
        }

        Assert.True(bodyStart >= 0, "Missing MCP response body separator.");
        using var document = JsonDocument.Parse(bytes.AsMemory(bodyStart));
        return document.RootElement.Clone();
    }

    private static ToolRegistry CreateRegistry()
    {
        var config = new AppConfig
        {
            DefaultClientProfile = "limited",
            ClientProfiles =
            [
                new() { Id = "limited", Permission = PermissionProfile.Limited, AllowedTools = ["credential_status"] }
            ]
        };
        var store = new FakeCredentialStore();
        var resolver = new CredentialResolver(store, new FakeCredentialPrompt(), maxAttempts: 1);
        var auditPath = Path.Combine(Path.GetTempPath(), "llm-pw-manager-tests", Guid.NewGuid().ToString("N"), "audit.jsonl");
        var audit = new AuditLogger(auditPath);

        return new ToolRegistry(
            config,
            new PolicyEvaluator(config),
            null!,
            new ApprovalCache(),
            audit,
            new AuditLogReader(auditPath),
            resolver,
            null!,
            null!,
            null!,
            null!,
            new ConfigSummary(config, store),
            "limited");
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
}

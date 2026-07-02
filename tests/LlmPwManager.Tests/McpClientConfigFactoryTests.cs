using System.Text.Json;
using LlmPwManager.Mcp;

namespace LlmPwManager.Tests;

public sealed class McpClientConfigFactoryTests
{
    [Fact]
    public void GenericConfigIncludesStdioCommandArgsAndHome()
    {
        var config = McpClientConfigFactory.Create("generic", "pw-broker", "C:\\broker-home", "limited");
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(config));
        var root = json.RootElement;

        Assert.Equal("pw-broker", root.GetProperty("name").GetString());
        Assert.Equal("stdio", root.GetProperty("transport").GetString());
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("command").GetString()));
        Assert.Equal("mcp", root.GetProperty("args")[0].GetString());
        Assert.Equal("C:\\broker-home", root.GetProperty("env").GetProperty("LLM_PW_MANAGER_HOME").GetString());
        Assert.Equal("limited", root.GetProperty("env").GetProperty("LLM_PW_MANAGER_CLIENT_PROFILE").GetString());
    }

    [Fact]
    public void McpServersConfigWrapsServerByName()
    {
        var config = McpClientConfigFactory.Create("mcpServers", "llm-pw-manager", null, null);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(config));

        var server = json.RootElement
            .GetProperty("mcpServers")
            .GetProperty("llm-pw-manager");

        Assert.False(string.IsNullOrWhiteSpace(server.GetProperty("command").GetString()));
        Assert.Equal("mcp", server.GetProperty("args")[0].GetString());
        Assert.Empty(server.GetProperty("env").EnumerateObject());
    }
}

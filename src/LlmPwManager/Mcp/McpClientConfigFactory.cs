namespace LlmPwManager.Mcp;

internal static class McpClientConfigFactory
{
    public const string HomeEnvironmentVariable = "LLM_PW_MANAGER_HOME";
    public const string ClientProfileEnvironmentVariable = "LLM_PW_MANAGER_CLIENT_PROFILE";

    public static object Create(string format, string serverName, string? appHome, string? clientProfile)
    {
        var server = new
        {
            command = ResolveExecutablePath(),
            args = new[] { "mcp" },
            env = BuildEnvironment(appHome, clientProfile)
        };

        return NormalizeFormat(format) switch
        {
            "mcpservers" => new
            {
                mcpServers = new Dictionary<string, object>
                {
                    [serverName] = server
                }
            },
            "generic" => new
            {
                name = serverName,
                transport = "stdio",
                server.command,
                server.args,
                server.env
            },
            _ => throw new InvalidOperationException("--format must be generic or mcpServers.")
        };
    }

    private static Dictionary<string, string> BuildEnvironment(string? appHome, string? clientProfile)
    {
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(appHome))
        {
            env[HomeEnvironmentVariable] = appHome;
        }

        if (!string.IsNullOrWhiteSpace(clientProfile))
        {
            env[ClientProfileEnvironmentVariable] = clientProfile;
        }

        return env;
    }

    private static string ResolveExecutablePath()
    {
        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath))
        {
            return Path.GetFullPath(processPath);
        }

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "LlmPwManager.exe"));
    }

    private static string NormalizeFormat(string value)
    {
        return value.Replace("-", "", StringComparison.OrdinalIgnoreCase)
            .Replace("_", "", StringComparison.OrdinalIgnoreCase)
            .ToLowerInvariant();
    }
}

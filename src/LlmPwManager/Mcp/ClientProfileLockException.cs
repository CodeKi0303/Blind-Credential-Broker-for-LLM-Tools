namespace LlmPwManager.Mcp;

internal sealed class ClientProfileLockException(string effectiveProfile)
    : InvalidOperationException("client_profile cannot override the profile locked for this MCP server.")
{
    public string EffectiveProfile { get; } = effectiveProfile;
}

using LlmPwManager.Config;

namespace LlmPwManager.Browser;

internal interface IBrowserLoginExecutor
{
    Task<BrowserLoginResult> LoginAsync(BrowserTarget target, CancellationToken cancellationToken);
}

internal sealed record BrowserLoginResult(bool Success, string Status, string? SafeMessage = null);

internal sealed class DisabledBrowserLoginExecutor : IBrowserLoginExecutor
{
    public Task<BrowserLoginResult> LoginAsync(BrowserTarget target, CancellationToken cancellationToken)
    {
        return Task.FromResult(new BrowserLoginResult(
            false,
            "browser_adapter_disabled",
            "Browser login requires an isolated adapter and is not enabled in the MVP."));
    }
}

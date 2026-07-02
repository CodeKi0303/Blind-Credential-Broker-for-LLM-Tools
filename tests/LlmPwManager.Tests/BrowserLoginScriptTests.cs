using LlmPwManager.Browser;
using LlmPwManager.Config;

namespace LlmPwManager.Tests;

public sealed class BrowserLoginScriptTests
{
    [Fact]
    public void ClearPasswordScriptDoesNotEmbedPasswordValue()
    {
        var target = new BrowserTarget
        {
            PasswordSelector = "#password"
        };

        var script = ManagedEdgeBrowserLoginExecutor.BuildClearPasswordScript(target);

        Assert.Contains("#password", script);
        Assert.Contains("password_cleared", script);
        Assert.Contains("pass.value = ''", script);
        Assert.DoesNotContain("super-secret-password", script);
    }

    [Fact]
    public void FillScriptEmbedsPasswordOnlyInFillPath()
    {
        var target = new BrowserTarget
        {
            UserName = "operator@example.com",
            UserNameSelector = "#email",
            PasswordSelector = "#password",
            SubmitSelector = "button[type=submit]",
            LoginTimeoutSeconds = 30
        };

        var fillScript = ManagedEdgeBrowserLoginExecutor.BuildFillScript(target, "super-secret-password");
        var clearScript = ManagedEdgeBrowserLoginExecutor.BuildClearPasswordScript(target);

        Assert.Contains("super-secret-password", fillScript);
        Assert.DoesNotContain("super-secret-password", clearScript);
    }

    [Fact]
    public void BrowserProfileCleanupDeletesRunDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "llm-pw-browser-profile-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "Cookies"), "session material");

        ManagedEdgeBrowserLoginExecutor.DeleteDirectoryBestEffort(directory);

        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public void BrowserProfileCleanupIgnoresMissingDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "llm-pw-browser-profile-missing-" + Guid.NewGuid().ToString("N"));

        ManagedEdgeBrowserLoginExecutor.DeleteDirectoryBestEffort(directory);

        Assert.False(Directory.Exists(directory));
    }
}

using LlmPwManager.Config;

namespace LlmPwManager.Tests;

public sealed class AppConfigStoreTests
{
    [Fact]
    public void SampleConfigIncludesSessionTools()
    {
        var directory = Path.Combine(Path.GetTempPath(), "llm-pw-manager-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "config.json");
        try
        {
            AppConfigStore.WriteSample(path, overwrite: false);
            var config = AppConfigStore.LoadOrCreate(path);

            var errors = AppConfigValidator.Validate(config);

            Assert.Empty(errors);
            Assert.Equal("limited", config.DefaultClientProfile);
            Assert.All(config.ClientProfiles, profile =>
            {
                Assert.Contains("ssh_open_session", profile.AllowedTools);
                Assert.Contains("session_list", profile.AllowedTools);
                Assert.Contains("session_close", profile.AllowedTools);
                Assert.Contains("browser_login", profile.AllowedTools);
                Assert.Contains("policy_check", profile.AllowedTools);
            });
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}

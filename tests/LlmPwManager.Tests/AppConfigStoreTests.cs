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
                Assert.Contains("ssh_register", profile.AllowedTools);
                Assert.Contains("session_list", profile.AllowedTools);
                Assert.Contains("session_close", profile.AllowedTools);
                Assert.Contains("db_register", profile.AllowedTools);
                Assert.Contains("browser_login", profile.AllowedTools);
                Assert.Contains("browser_register", profile.AllowedTools);
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

    [Fact]
    public async Task ConcurrentUpdatesPreserveAllChanges()
    {
        var directory = Path.Combine(Path.GetTempPath(), "llm-pw-manager-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "config.json");
        try
        {
            AppConfigStore.WriteSample(path, overwrite: true);
            using var start = new ManualResetEventSlim(false);
            var tasks = Enumerable.Range(1, 40)
                .Select(index => Task.Run(() =>
                {
                    start.Wait();
                    AppConfigStore.Update(path, config =>
                    {
                        ConfigMutator.AddCredential(config, $"race-{index}", $"user{index}", $"Race {index}");
                        AppConfigValidator.ThrowIfInvalid(config);
                    });
                }))
                .ToArray();

            start.Set();
            await Task.WhenAll(tasks);

            var config = AppConfigStore.LoadOrCreate(path);

            Assert.Equal(40, config.Credentials.Count(credential => credential.Alias.StartsWith("race-", StringComparison.Ordinal)));
            for (var index = 1; index <= 40; index++)
            {
                Assert.Contains(config.Credentials, credential => credential.Alias == $"race-{index}");
            }
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void LoadMigratesDefaultProfilesToCurrentMcpToolSet()
    {
        var directory = Path.Combine(Path.GetTempPath(), "llm-pw-manager-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "config.json");
        try
        {
            AppConfigStore.Save(path, new AppConfig
            {
                DefaultClientProfile = "limited",
                ClientProfiles =
                [
                    new()
                    {
                        Id = "full",
                        Permission = PermissionProfile.Full,
                        AllowedTools = ["ssh_run", "db_query", "route_test", "credential_status", "config_summary"]
                    },
                    new()
                    {
                        Id = "limited",
                        Permission = PermissionProfile.Limited,
                        AllowedTools = ["ssh_run", "db_query", "route_test", "credential_status", "config_summary"]
                    },
                    new()
                    {
                        Id = "custom-readonly",
                        Permission = PermissionProfile.Limited,
                        AllowedTools = ["config_summary"]
                    }
                ]
            });

            var config = AppConfigStore.LoadOrCreate(path);

            var full = config.ClientProfiles.Single(profile => profile.Id == "full");
            var limited = config.ClientProfiles.Single(profile => profile.Id == "limited");
            var custom = config.ClientProfiles.Single(profile => profile.Id == "custom-readonly");

            Assert.Contains("ssh_register", full.AllowedTools);
            Assert.Contains("db_register", full.AllowedTools);
            Assert.Contains("browser_register", full.AllowedTools);
            Assert.Contains("ssh_open_session", limited.AllowedTools);
            Assert.Contains("audit_tail", limited.AllowedTools);
            Assert.DoesNotContain("ssh_register", custom.AllowedTools);
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

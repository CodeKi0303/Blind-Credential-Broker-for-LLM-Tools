namespace LlmPwManager.App;

internal static class AppPaths
{
    public static string EnsureAppDirectory()
    {
        var overrideDirectory = Environment.GetEnvironmentVariable("LLM_PW_MANAGER_HOME");
        var directory = !string.IsNullOrWhiteSpace(overrideDirectory)
            ? Environment.ExpandEnvironmentVariables(overrideDirectory)
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "LlmPwManager");
        Directory.CreateDirectory(directory);
        return directory;
    }
}

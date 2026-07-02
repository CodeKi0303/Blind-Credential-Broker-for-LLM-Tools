using LlmPwManager.App;
using LlmPwManager.Security;

return await ProgramEntry.MainAsync(args);

internal static class ProgramEntry
{
    public static async Task<int> MainAsync(string[] args)
    {
        try
        {
            return await AppHost.RunAsync(args, CancellationToken.None);
        }
        catch (Exception ex)
        {
            var safeError = SafeErrorFactory.FromException(ex);
            Console.Error.WriteLine($"fatal: {safeError.Code}: {safeError.Message}");
            return 1;
        }
    }
}

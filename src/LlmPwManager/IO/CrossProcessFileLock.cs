namespace LlmPwManager.IO;

internal sealed class CrossProcessFileLock : IDisposable
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
    private readonly FileStream stream;

    private CrossProcessFileLock(FileStream stream)
    {
        this.stream = stream;
    }

    public static CrossProcessFileLock Acquire(string targetPath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(targetPath));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var lockPath = targetPath + ".lock";
        var deadline = DateTimeOffset.UtcNow.Add(DefaultTimeout);
        IOException? lastIoException = null;

        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                var stream = new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None);
                return new CrossProcessFileLock(stream);
            }
            catch (IOException ex)
            {
                lastIoException = ex;
                Thread.Sleep(50);
            }
        }

        throw new IOException($"Timed out waiting for file lock: {lockPath}", lastIoException);
    }

    public void Dispose()
    {
        stream.Dispose();
    }
}

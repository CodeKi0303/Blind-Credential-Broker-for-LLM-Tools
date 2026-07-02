using LlmPwManager.Security;

namespace LlmPwManager.Tests;

public sealed class SafeErrorFactoryTests
{
    [Fact]
    public void UnknownExceptionDoesNotExposeOriginalMessage()
    {
        var error = SafeErrorFactory.FromException(new Exception("Password=super-secret;Host=db"));

        Assert.Equal("execution_failed", error.Code);
        Assert.DoesNotContain("super-secret", error.Message);
        Assert.DoesNotContain("Host=db", error.Message);
    }

    [Fact]
    public void InvalidOperationExceptionUsesGenericOperationFailure()
    {
        var error = SafeErrorFactory.FromException(new InvalidOperationException("connection string contains Password=secret"));

        Assert.Equal("operation_failed", error.Code);
        Assert.DoesNotContain("secret", error.Message);
    }

    [Fact]
    public void CancellationHasStableCode()
    {
        var error = SafeErrorFactory.FromException(new OperationCanceledException("cancelled"));

        Assert.Equal("operation_cancelled", error.Code);
        Assert.Equal("Operation was cancelled.", error.Message);
    }
}

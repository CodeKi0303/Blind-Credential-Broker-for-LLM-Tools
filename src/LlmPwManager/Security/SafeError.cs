namespace LlmPwManager.Security;

internal sealed record SafeError(string Code, string Message);

internal static class SafeErrorFactory
{
    public static SafeError FromException(Exception exception)
    {
        return exception switch
        {
            OperationCanceledException => new SafeError("operation_cancelled", "Operation was cancelled."),
            ArgumentException => new SafeError("invalid_request", "The request was invalid."),
            InvalidOperationException => new SafeError("operation_failed", "The requested operation could not be completed."),
            NotSupportedException => new SafeError("unsupported_operation", "The requested operation is not supported."),
            _ => new SafeError("execution_failed", "The operation failed. Details were withheld to avoid exposing secrets.")
        };
    }
}

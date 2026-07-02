using LlmPwManager.Security;

namespace LlmPwManager.Tests;

public sealed class SecretRedactorTests
{
    [Fact]
    public void RedactsKnownSecretsFromOutput()
    {
        var redactor = new SecretRedactor();

        var result = redactor.Redact("token=s3cr3t password=s3cr3t", ["s3cr3t"]);

        Assert.Equal("token=[REDACTED] password=[REDACTED]", result);
    }

    [Fact]
    public void RedactsSecretLikeAssignmentsFromOutput()
    {
        var redactor = new SecretRedactor();

        var result = redactor.Redact("PASSWORD=super-secret token:'abc123' api_key=\"key-secret\" access_key=access-secret private-key:private-secret clientSecret=client-secret credential=credential-secret keep=value");

        Assert.Contains("PASSWORD=[REDACTED]", result);
        Assert.Contains("token=[REDACTED]", result);
        Assert.Contains("api_key=[REDACTED]", result);
        Assert.Contains("access_key=[REDACTED]", result);
        Assert.Contains("private-key=[REDACTED]", result);
        Assert.Contains("clientSecret=[REDACTED]", result);
        Assert.Contains("credential=[REDACTED]", result);
        Assert.Contains("keep=value", result);
        Assert.DoesNotContain("super-secret", result);
        Assert.DoesNotContain("abc123", result);
        Assert.DoesNotContain("key-secret", result);
        Assert.DoesNotContain("access-secret", result);
        Assert.DoesNotContain("private-secret", result);
        Assert.DoesNotContain("client-secret", result);
        Assert.DoesNotContain("credential-secret", result);
    }

    [Fact]
    public void RedactsUriUserInfoFromOutput()
    {
        var redactor = new SecretRedactor();

        var result = redactor.Redact("postgres://user:uri-secret@db/app");

        Assert.Equal("postgres://[REDACTED]@db/app", result);
    }

    [Fact]
    public void IgnoresEmptySecretValues()
    {
        var redactor = new SecretRedactor();

        var result = redactor.Redact("abc", [""]);

        Assert.Equal("abc", result);
    }
}

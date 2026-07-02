using LlmPwManager.Credentials;
using LlmPwManager.Ui;

namespace LlmPwManager.Tests;

public sealed class CredentialResolverTests
{
    [Fact]
    public async Task MissingCredentialPromptsTestsAndStoresOnSuccess()
    {
        var store = new FakeCredentialStore();
        var prompt = new FakeCredentialPrompt(["correct"]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        var secret = await resolver.ResolveAsync(
            "db-readonly",
            "DB readonly",
            "readonly",
            candidate => Task.FromResult(new CredentialTestResult(candidate == "correct")),
            CancellationToken.None);

        Assert.Equal("correct", secret);
        Assert.Equal("correct", store.GetSecret("db-readonly"));
        Assert.Equal(1, prompt.RequestCount);
    }

    [Fact]
    public async Task FailedCredentialTestPromptsAgainWithoutStoringBadValue()
    {
        var store = new FakeCredentialStore();
        var prompt = new FakeCredentialPrompt(["wrong", "correct"]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        var secret = await resolver.ResolveAsync(
            "ssh-prod",
            "SSH prod",
            "deploy",
            candidate => Task.FromResult(new CredentialTestResult(candidate == "correct")),
            CancellationToken.None);

        Assert.Equal("correct", secret);
        Assert.Equal("correct", store.GetSecret("ssh-prod"));
        Assert.DoesNotContain("wrong", store.SavedValues);
        Assert.Equal(2, prompt.RequestCount);
    }

    [Fact]
    public async Task FailedCredentialTestShowsSafeReasonOnNextPrompt()
    {
        var store = new FakeCredentialStore();
        var prompt = new FakeCredentialPrompt(["wrong", "correct"]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        var secret = await resolver.ResolveAsync(
            "db-readonly",
            "DB readonly",
            "readonly",
            candidate => Task.FromResult(candidate == "correct"
                ? new CredentialTestResult(true)
                : new CredentialTestResult(false, "authentication failed for readonly")),
            CancellationToken.None);

        Assert.Equal("correct", secret);
        Assert.Equal(2, prompt.Reasons.Count);
        Assert.Equal("Credential is missing or no longer valid.", prompt.Reasons[0]);
        Assert.Contains("authentication failed for readonly", prompt.Reasons[1]);
    }

    [Fact]
    public async Task PromptReasonRedactsCandidateIfTesterReturnsIt()
    {
        var store = new FakeCredentialStore();
        var prompt = new FakeCredentialPrompt(["wrong-password", "correct"]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        await resolver.ResolveAsync(
            "ssh-prod",
            "SSH prod",
            "deploy",
            candidate => Task.FromResult(candidate == "correct"
                ? new CredentialTestResult(true)
                : new CredentialTestResult(false, $"password {candidate} was rejected")),
            CancellationToken.None);

        Assert.Contains("[REDACTED]", prompt.Reasons[1]);
        Assert.DoesNotContain("wrong-password", prompt.Reasons[1]);
    }

    [Fact]
    public async Task ExistingInvalidCredentialShowsSafeReasonOnFirstPrompt()
    {
        var store = new FakeCredentialStore();
        store.SaveSecret("ssh-prod", "old-password");
        var prompt = new FakeCredentialPrompt(["new-password"]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        await resolver.ResolveAsync(
            "ssh-prod",
            "SSH prod",
            "deploy",
            candidate => Task.FromResult(candidate == "new-password"
                ? new CredentialTestResult(true)
                : new CredentialTestResult(false, "stored credential was rejected")),
            CancellationToken.None);

        Assert.Single(prompt.Reasons);
        Assert.Contains("Stored credential test failed", prompt.Reasons[0]);
        Assert.Contains("stored credential was rejected", prompt.Reasons[0]);
    }

    [Fact]
    public async Task ExistingValidCredentialDoesNotPrompt()
    {
        var store = new FakeCredentialStore();
        store.SaveSecret("ssh-prod", "existing");
        var prompt = new FakeCredentialPrompt(["unused"]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        var secret = await resolver.ResolveAsync(
            "ssh-prod",
            "SSH prod",
            "deploy",
            candidate => Task.FromResult(new CredentialTestResult(candidate == "existing")),
            CancellationToken.None);

        Assert.Equal("existing", secret);
        Assert.Equal(0, prompt.RequestCount);
    }

    [Fact]
    public async Task ExistingInvalidCredentialIsDeletedAndReplaced()
    {
        var store = new FakeCredentialStore();
        store.SaveSecret("ssh-prod", "old");
        var prompt = new FakeCredentialPrompt(["new"]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        var secret = await resolver.ResolveAsync(
            "ssh-prod",
            "SSH prod",
            "deploy",
            candidate => Task.FromResult(new CredentialTestResult(candidate == "new")),
            CancellationToken.None);

        Assert.Equal("new", secret);
        Assert.Equal("new", store.GetSecret("ssh-prod"));
        Assert.Contains("ssh-prod", store.DeletedAliases);
    }

    [Fact]
    public async Task UserCancellationReturnsCredentialUnavailable()
    {
        var store = new FakeCredentialStore();
        var prompt = new FakeCredentialPrompt([null]);
        var resolver = new CredentialResolver(store, prompt, maxAttempts: 3);

        var ex = await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            resolver.ResolveAsync(
                "ssh-prod",
                "SSH prod",
                "deploy",
                _ => Task.FromResult(new CredentialTestResult(true)),
                CancellationToken.None));

        Assert.Equal("ssh-prod", ex.Alias);
        Assert.False(store.Exists("ssh-prod"));
    }

    [Fact]
    public void ForgetDeletesExistingCredentialAndReportsItExisted()
    {
        var store = new FakeCredentialStore();
        store.SaveSecret("ssh-prod", "secret");
        var resolver = new CredentialResolver(store, new FakeCredentialPrompt([]), maxAttempts: 3);

        var existed = resolver.Forget("ssh-prod");

        Assert.True(existed);
        Assert.False(store.Exists("ssh-prod"));
        Assert.Contains("ssh-prod", store.DeletedAliases);
    }

    [Fact]
    public void ForgetMissingCredentialStillDeletesAliasAndReportsMissing()
    {
        var store = new FakeCredentialStore();
        var resolver = new CredentialResolver(store, new FakeCredentialPrompt([]), maxAttempts: 3);

        var existed = resolver.Forget("ssh-prod");

        Assert.False(existed);
        Assert.False(store.Exists("ssh-prod"));
        Assert.Contains("ssh-prod", store.DeletedAliases);
    }

    private sealed class FakeCredentialStore : ICredentialStore
    {
        private readonly Dictionary<string, string> secrets = new(StringComparer.OrdinalIgnoreCase);

        public List<string> SavedValues { get; } = [];
        public List<string> DeletedAliases { get; } = [];

        public bool Exists(string alias) => secrets.ContainsKey(alias);
        public string? GetSecret(string alias) => secrets.GetValueOrDefault(alias);

        public void SaveSecret(string alias, string secret)
        {
            secrets[alias] = secret;
            SavedValues.Add(secret);
        }

        public void DeleteSecret(string alias)
        {
            secrets.Remove(alias);
            DeletedAliases.Add(alias);
        }
    }

    private sealed class FakeCredentialPrompt(IEnumerable<string?> responses) : ICredentialPrompt
    {
        private readonly Queue<string?> responses = new(responses);

        public int RequestCount { get; private set; }
        public List<string> Reasons { get; } = [];

        public string? RequestPassword(string alias, string label, string userName, string reason)
        {
            RequestCount++;
            Reasons.Add(reason);
            return responses.Count == 0 ? null : responses.Dequeue();
        }
    }
}

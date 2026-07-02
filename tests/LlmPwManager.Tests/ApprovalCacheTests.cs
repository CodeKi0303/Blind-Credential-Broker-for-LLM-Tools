using LlmPwManager.Policy;

namespace LlmPwManager.Tests;

public sealed class ApprovalCacheTests
{
    [Fact]
    public void RememberedApprovalIsReturnedForSameKey()
    {
        var cache = new ApprovalCache();

        cache.Remember("approval", "title", "target", "action", "reason");

        Assert.True(cache.IsApproved("approval", "title", "target", "action", "reason"));
    }

    [Fact]
    public void DifferentActionIsNotApproved()
    {
        var cache = new ApprovalCache();

        cache.Remember("approval", "title", "target", "action", "reason");

        Assert.False(cache.IsApproved("approval", "title", "target", "different", "reason"));
    }

    [Fact]
    public void DifferentClientProfileIsNotApproved()
    {
        var cache = new ApprovalCache();

        cache.Remember("approval", "title", "target", "action", "reason");

        Assert.False(cache.IsApproved("limited", "title", "target", "action", "reason"));
    }
}

namespace LlmPwManager.Policy;

internal sealed class ApprovalCache
{
    private readonly object gate = new();
    private readonly HashSet<ApprovalCacheKey> approved = [];

    public bool IsApproved(string clientProfile, string title, string target, string action, string reason)
    {
        lock (gate)
        {
            return approved.Contains(new ApprovalCacheKey(clientProfile, title, target, action, reason));
        }
    }

    public void Remember(string clientProfile, string title, string target, string action, string reason)
    {
        lock (gate)
        {
            approved.Add(new ApprovalCacheKey(clientProfile, title, target, action, reason));
        }
    }
}

internal sealed record ApprovalCacheKey(
    string ClientProfile,
    string Title,
    string Target,
    string Action,
    string Reason);

using LlmPwManager.Config;
using LlmPwManager.Policy;

namespace LlmPwManager.Tests;

public sealed class PolicyEvaluatorTests
{
    [Fact]
    public void LimitedProfileAllowsMatchingReadOnlySshCommand()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_run",
            "limited",
            RouteId: "prod-web",
            Command: "systemctl status nginx"));

        Assert.True(decision.Allowed);
        Assert.False(decision.NeedsApproval);
    }

    [Fact]
    public void LimitedProfileAllowsMatchingReadOnlySudoCommand()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_sudo_run",
            "limited",
            RouteId: "prod-web",
            Command: "systemctl status nginx"));

        Assert.True(decision.Allowed);
        Assert.False(decision.NeedsApproval);
    }

    [Fact]
    public void ToolNameAndAllowedToolsAreCaseInsensitive()
    {
        var config = CreateConfig();
        config.ClientProfiles[0].AllowedTools = ["SSH_RUN"];
        config.Policies[0].Tools = ["SSH_RUN"];
        var evaluator = new PolicyEvaluator(config);

        var decision = evaluator.Evaluate(new ToolRequest(
            "SSH_RUN",
            "limited",
            RouteId: "prod-web",
            Command: "uptime"));

        Assert.True(decision.Allowed);
    }

    [Fact]
    public void UnknownProfileIsDeniedInsteadOfFallingBackToDefault()
    {
        var config = CreateConfig();
        config.DefaultClientProfile = "full";
        config.ClientProfiles.Add(new ClientProfile
        {
            Id = "full",
            Permission = PermissionProfile.Full,
            AllowedTools = []
        });
        var evaluator = new PolicyEvaluator(config);

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_run",
            "limtied",
            RouteId: "prod-web",
            Command: "uptime"));

        Assert.False(decision.Allowed);
        Assert.False(decision.NeedsApproval);
        Assert.Equal("unknown client profile", decision.Reason);
    }

    [Fact]
    public void LimitedProfileDeniesUnmatchedSshCommand()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_run",
            "limited",
            RouteId: "prod-web",
            Command: "rm -rf /tmp/example"));

        Assert.False(decision.Allowed);
        Assert.False(decision.NeedsApproval);
        Assert.Equal("no matching policy rule", decision.Reason);
    }

    [Fact]
    public void LimitedProfileDeniesSudoCommandWithoutPolicy()
    {
        var config = CreateConfig();
        config.Policies.RemoveAll(policy => policy.Tools.Contains("ssh_sudo_run"));
        var evaluator = new PolicyEvaluator(config);

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_sudo_run",
            "limited",
            RouteId: "prod-web",
            Command: "systemctl status nginx"));

        Assert.False(decision.Allowed);
        Assert.Equal("no matching policy rule", decision.Reason);
    }

    [Fact]
    public void LimitedProfileDeniesShellChainingEvenWhenPrefixMatches()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_run",
            "limited",
            RouteId: "prod-web",
            Command: "df -h; rm -rf /tmp/example"));

        Assert.False(decision.Allowed);
        Assert.Equal("shell operators are not allowed by policy", decision.Reason);
    }

    [Fact]
    public void LimitedProfileDeniesSudoShellChainingEvenWhenPrefixMatches()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_sudo_run",
            "limited",
            RouteId: "prod-web",
            Command: "systemctl status nginx; cat /etc/shadow"));

        Assert.False(decision.Allowed);
        Assert.Equal("shell operators are not allowed by policy", decision.Reason);
    }

    [Fact]
    public void PolicyCanExplicitlyAllowShellOperators()
    {
        var config = CreateConfig();
        config.Policies[0].AllowShellOperators = true;
        var evaluator = new PolicyEvaluator(config);

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_run",
            "limited",
            RouteId: "prod-web",
            Command: "df -h | head"));

        Assert.True(decision.Allowed);
    }

    [Fact]
    public void SshPolicyWithoutPrefixesStillDeniesShellOperators()
    {
        var config = CreateConfig();
        config.Policies[0].CommandPrefixes = [];
        var evaluator = new PolicyEvaluator(config);

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_run",
            "limited",
            RouteId: "prod-web",
            Command: "uptime && whoami"));

        Assert.False(decision.Allowed);
        Assert.Equal("shell operators are not allowed by policy", decision.Reason);
    }

    [Fact]
    public void LimitedProfileDeniesWriteSqlEvenWhenConnectionMatches()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "db_query",
            "limited",
            ConnectionId: "prod-db",
            Sql: "DELETE FROM users WHERE id = 1"));

        Assert.False(decision.Allowed);
        Assert.False(decision.NeedsApproval);
        Assert.Equal("only single read-only SQL statements are allowed by policy", decision.Reason);
    }

    [Fact]
    public void ApprovalProfileRequestsApprovalInsteadOfRunningUnknownAction()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "ssh_run",
            "approval",
            RouteId: "prod-web",
            Command: "journalctl -u nginx"));

        Assert.False(decision.Allowed);
        Assert.True(decision.NeedsApproval);
    }

    [Fact]
    public void LimitedProfileAllowsMatchingBrowserTarget()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "browser_login",
            "limited",
            BrowserTargetId: "admin-console"));

        Assert.True(decision.Allowed);
        Assert.False(decision.NeedsApproval);
    }

    [Fact]
    public void LimitedProfileDeniesUnmatchedBrowserTarget()
    {
        var evaluator = new PolicyEvaluator(CreateConfig());

        var decision = evaluator.Evaluate(new ToolRequest(
            "browser_login",
            "limited",
            BrowserTargetId: "billing-console"));

        Assert.False(decision.Allowed);
        Assert.Equal("no matching policy rule", decision.Reason);
    }

    private static AppConfig CreateConfig() => new()
    {
        DefaultClientProfile = "limited",
        ClientProfiles =
        [
            new() { Id = "limited", Permission = PermissionProfile.Limited, AllowedTools = ["ssh_run", "ssh_sudo_run", "db_query", "browser_login"] },
            new() { Id = "approval", Permission = PermissionProfile.Approval, AllowedTools = ["ssh_run", "ssh_sudo_run", "db_query", "browser_login"] }
        ],
        Policies =
        [
            new()
            {
                Id = "safe-ssh",
                Tools = ["ssh_run"],
                RouteIds = ["prod-web"],
                CommandPrefixes = ["systemctl status", "df", "uptime"],
                MinPermission = PermissionProfile.Limited
            },
            new()
            {
                Id = "safe-sudo-ssh",
                Tools = ["ssh_sudo_run"],
                RouteIds = ["prod-web"],
                CommandPrefixes = ["systemctl status", "journalctl", "cat ", "head ", "tail ", "ls "],
                MinPermission = PermissionProfile.Limited
            },
            new()
            {
                Id = "safe-db",
                Tools = ["db_query"],
                ConnectionIds = ["prod-db"],
                AllowWriteSql = false,
                MinPermission = PermissionProfile.Limited
            },
            new()
            {
                Id = "safe-browser",
                Tools = ["browser_login"],
                BrowserTargetIds = ["admin-console"],
                MinPermission = PermissionProfile.Limited
            }
        ]
    };
}

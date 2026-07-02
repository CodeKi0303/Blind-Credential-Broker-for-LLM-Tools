using LlmPwManager.Policy;

namespace LlmPwManager.Tests;

public sealed class ShellCommandSafetyTests
{
    [Theory]
    [InlineData("df -h")]
    [InlineData("systemctl status nginx --no-pager")]
    [InlineData("echo 'a;b'")]
    public void SimpleCommandsAreAllowed(string command)
    {
        Assert.False(ShellCommandSafety.ContainsShellOperator(command));
    }

    [Theory]
    [InlineData("df -h; rm -rf /tmp/x")]
    [InlineData("df -h && rm -rf /tmp/x")]
    [InlineData("df -h | head")]
    [InlineData("echo $(cat /etc/passwd)")]
    [InlineData("echo `cat /etc/passwd`")]
    [InlineData("cat < /etc/passwd")]
    [InlineData("echo x > /tmp/x")]
    public void ShellOperatorsAreDetected(string command)
    {
        Assert.True(ShellCommandSafety.ContainsShellOperator(command));
    }
}

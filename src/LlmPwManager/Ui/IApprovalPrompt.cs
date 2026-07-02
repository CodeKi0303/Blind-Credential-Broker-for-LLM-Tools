namespace LlmPwManager.Ui;

internal interface IApprovalPrompt
{
    bool Approve(string title, string target, string action, string reason);
}

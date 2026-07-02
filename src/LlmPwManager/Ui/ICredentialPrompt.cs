namespace LlmPwManager.Ui;

internal interface ICredentialPrompt
{
    string? RequestPassword(string alias, string label, string userName, string reason);
}

namespace LlmPwManager.Credentials;

internal interface ICredentialStore
{
    bool Exists(string alias);
    string? GetSecret(string alias);
    void SaveSecret(string alias, string secret);
    void DeleteSecret(string alias);
}

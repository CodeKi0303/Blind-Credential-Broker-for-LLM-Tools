namespace LlmPwManager.Config;

internal static class ConfigIdentifier
{
    public const int MaxLength = 128;
    public const string AllowedDescription = "letters, numbers, dot, underscore, or dash";

    public static bool IsValid(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxLength)
        {
            return false;
        }

        return value.All(character =>
            char.IsAsciiLetterOrDigit(character) ||
            character is '.' or '_' or '-');
    }

    public static string Error(string label, string value) =>
        $"{label} '{value}' is invalid; use {AllowedDescription} and keep it at most {MaxLength} characters.";
}

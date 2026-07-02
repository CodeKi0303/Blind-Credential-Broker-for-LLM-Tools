using LlmPwManager.Config;

namespace LlmPwManager.Policy;

internal sealed class PolicyEvaluator(AppConfig config)
{
    public PolicyDecision Evaluate(ToolRequest request)
    {
        var toolName = request.ToolName.Trim().ToLowerInvariant();
        var profile = config.ClientProfiles.FirstOrDefault(p => p.Id.Equals(request.ClientProfileId, StringComparison.OrdinalIgnoreCase));
        if (profile is null)
        {
            return PolicyDecision.Deny("unknown client profile");
        }

        var permission = profile.Permission;
        if (profile.AllowedTools.Count > 0 &&
            !profile.AllowedTools.Contains(toolName, StringComparer.OrdinalIgnoreCase))
        {
            return PolicyDecision.Deny("tool is not allowed for this client profile");
        }

        if (permission == PermissionProfile.Full)
        {
            return PolicyDecision.Allow();
        }

        var matchingRules = config.Policies.Where(rule =>
            Matches(rule.Tools, toolName) &&
            Matches(rule.RouteIds, request.RouteId) &&
            Matches(rule.ConnectionIds, request.ConnectionId) &&
            Matches(rule.BrowserTargetIds, request.BrowserTargetId));

        foreach (var rule in matchingRules)
        {
            if (Rank(permission) < Rank(rule.MinPermission))
            {
                continue;
            }

            if (toolName == "ssh_run" && rule.CommandPrefixes.Count > 0)
            {
                if (!rule.AllowShellOperators && ShellCommandSafety.ContainsShellOperator(request.Command))
                {
                    return PolicyDecision.Deny("shell operators are not allowed by policy");
                }

                if (!rule.CommandPrefixes.Any(prefix => request.Command.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }
            }
            else if (toolName == "ssh_run" && !rule.AllowShellOperators && ShellCommandSafety.ContainsShellOperator(request.Command))
            {
                return PolicyDecision.Deny("shell operators are not allowed by policy");
            }

            if (toolName == "db_query" && !rule.AllowWriteSql && !SqlClassifier.IsSingleReadOnlyStatement(request.Sql))
            {
                return PolicyDecision.Deny("only single read-only SQL statements are allowed by policy");
            }

            return PolicyDecision.Allow();
        }

        return permission switch
        {
            PermissionProfile.Approval => PolicyDecision.ApprovalRequired("approval profile requires explicit approval"),
            _ => PolicyDecision.Deny("no matching policy rule")
        };
    }

    private static bool Matches(List<string> values, string? actual)
    {
        return values.Count == 0 ||
            (actual is not null && values.Contains(actual, StringComparer.OrdinalIgnoreCase));
    }

    private static int Rank(PermissionProfile profile) => profile switch
    {
        PermissionProfile.DenyByDefault => 0,
        PermissionProfile.Approval => 1,
        PermissionProfile.Limited => 2,
        PermissionProfile.Full => 3,
        _ => 0
    };
}

internal sealed record ToolRequest(
    string ToolName,
    string ClientProfileId,
    string? RouteId = null,
    string? ConnectionId = null,
    string? BrowserTargetId = null,
    string Command = "",
    string Sql = "");

internal sealed record PolicyDecision(bool Allowed, bool NeedsApproval, string? Reason)
{
    public static PolicyDecision Allow() => new(true, false, null);
    public static PolicyDecision Deny(string reason) => new(false, false, reason);
    public static PolicyDecision ApprovalRequired(string reason) => new(false, true, reason);
}

internal static class SqlClassifier
{
    private static readonly string[] ReadPrefixes =
    [
        "select", "with", "show", "describe", "desc", "explain"
    ];

    private static readonly string[] WriteKeywords =
    [
        "insert", "update", "delete", "merge", "alter", "drop", "truncate", "create", "grant", "revoke", "call", "copy"
    ];

    public static bool IsWriteSql(string sql)
    {
        return !IsSingleReadOnlyStatement(sql);
    }

    public static bool IsSingleReadOnlyStatement(string sql)
    {
        var statements = SplitStatements(sql).Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
        if (statements.Count != 1)
        {
            return false;
        }

        var normalized = StripCommentsAndTrim(statements[0]);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return false;
        }

        var firstWord = ReadFirstWord(normalized);
        if (!ReadPrefixes.Contains(firstWord, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        return !ContainsWriteKeyword(normalized);
    }

    private static bool ContainsWriteKeyword(string sql)
    {
        foreach (var token in TokenizeWords(sql))
        {
            if (WriteKeywords.Contains(token, StringComparer.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<string> SplitStatements(string sql)
    {
        var start = 0;
        var state = SqlScanState.Normal;
        for (var i = 0; i < sql.Length; i++)
        {
            var c = sql[i];
            var next = i + 1 < sql.Length ? sql[i + 1] : '\0';

            if (state == SqlScanState.Normal)
            {
                if (c == '\'' )
                {
                    state = SqlScanState.SingleQuote;
                }
                else if (c == '"')
                {
                    state = SqlScanState.DoubleQuote;
                }
                else if (c == '-' && next == '-')
                {
                    state = SqlScanState.LineComment;
                    i++;
                }
                else if (c == '/' && next == '*')
                {
                    state = SqlScanState.BlockComment;
                    i++;
                }
                else if (c == ';')
                {
                    yield return sql[start..i];
                    start = i + 1;
                }
            }
            else if (state == SqlScanState.SingleQuote)
            {
                if (c == '\'' && next == '\'')
                {
                    i++;
                }
                else if (c == '\'')
                {
                    state = SqlScanState.Normal;
                }
            }
            else if (state == SqlScanState.DoubleQuote)
            {
                if (c == '"')
                {
                    state = SqlScanState.Normal;
                }
            }
            else if (state == SqlScanState.LineComment)
            {
                if (c == '\n')
                {
                    state = SqlScanState.Normal;
                }
            }
            else if (state == SqlScanState.BlockComment)
            {
                if (c == '*' && next == '/')
                {
                    state = SqlScanState.Normal;
                    i++;
                }
            }
        }

        yield return sql[start..];
    }

    private static string StripCommentsAndTrim(string sql)
    {
        var output = new List<char>(sql.Length);
        var state = SqlScanState.Normal;
        for (var i = 0; i < sql.Length; i++)
        {
            var c = sql[i];
            var next = i + 1 < sql.Length ? sql[i + 1] : '\0';

            if (state == SqlScanState.Normal)
            {
                if (c == '\'')
                {
                    state = SqlScanState.SingleQuote;
                    output.Add(c);
                }
                else if (c == '"')
                {
                    state = SqlScanState.DoubleQuote;
                    output.Add(c);
                }
                else if (c == '-' && next == '-')
                {
                    state = SqlScanState.LineComment;
                    i++;
                }
                else if (c == '/' && next == '*')
                {
                    state = SqlScanState.BlockComment;
                    i++;
                }
                else
                {
                    output.Add(c);
                }
            }
            else if (state == SqlScanState.SingleQuote)
            {
                output.Add(c);
                if (c == '\'' && next == '\'')
                {
                    output.Add(next);
                    i++;
                }
                else if (c == '\'')
                {
                    state = SqlScanState.Normal;
                }
            }
            else if (state == SqlScanState.DoubleQuote)
            {
                output.Add(c);
                if (c == '"')
                {
                    state = SqlScanState.Normal;
                }
            }
            else if (state == SqlScanState.LineComment)
            {
                if (c == '\n')
                {
                    state = SqlScanState.Normal;
                    output.Add(' ');
                }
            }
            else if (state == SqlScanState.BlockComment)
            {
                if (c == '*' && next == '/')
                {
                    state = SqlScanState.Normal;
                    output.Add(' ');
                    i++;
                }
            }
        }

        return new string(output.ToArray()).Trim();
    }

    private static string ReadFirstWord(string sql)
    {
        return TokenizeWords(sql).FirstOrDefault() ?? "";
    }

    private static IEnumerable<string> TokenizeWords(string sql)
    {
        var words = new List<string>();
        var state = SqlScanState.Normal;
        var token = new List<char>();

        for (var i = 0; i < sql.Length; i++)
        {
            var c = sql[i];
            var next = i + 1 < sql.Length ? sql[i + 1] : '\0';

            if (state == SqlScanState.Normal)
            {
                if (c == '\'')
                {
                    Flush();
                    state = SqlScanState.SingleQuote;
                }
                else if (c == '"')
                {
                    Flush();
                    state = SqlScanState.DoubleQuote;
                }
                else if (char.IsLetterOrDigit(c) || c == '_')
                {
                    token.Add(c);
                }
                else
                {
                    Flush();
                }
            }
            else if (state == SqlScanState.SingleQuote)
            {
                if (c == '\'' && next == '\'')
                {
                    i++;
                }
                else if (c == '\'')
                {
                    state = SqlScanState.Normal;
                }
            }
            else if (state == SqlScanState.DoubleQuote && c == '"')
            {
                state = SqlScanState.Normal;
            }
        }

        Flush();

        void Flush()
        {
            if (token.Count == 0)
            {
                return;
            }

            var value = new string(token.ToArray());
            token.Clear();
            words.Add(value);
        }

        return words;
    }

    private enum SqlScanState
    {
        Normal,
        SingleQuote,
        DoubleQuote,
        LineComment,
        BlockComment
    }
}

internal static class ShellCommandSafety
{
    public static bool ContainsShellOperator(string command)
    {
        var state = ShellScanState.Normal;
        for (var i = 0; i < command.Length; i++)
        {
            var c = command[i];
            var next = i + 1 < command.Length ? command[i + 1] : '\0';

            if (state == ShellScanState.Normal)
            {
                if (c == '\'')
                {
                    state = ShellScanState.SingleQuote;
                }
                else if (c == '"')
                {
                    state = ShellScanState.DoubleQuote;
                }
                else if (c is ';' or '|' or '&' or '`' or '>' or '<' or '\n' or '\r')
                {
                    return true;
                }
                else if (c == '$' && next == '(')
                {
                    return true;
                }
            }
            else if (state == ShellScanState.SingleQuote && c == '\'')
            {
                state = ShellScanState.Normal;
            }
            else if (state == ShellScanState.DoubleQuote)
            {
                if (c == '"')
                {
                    state = ShellScanState.Normal;
                }
                else if (c is '`')
                {
                    return true;
                }
                else if (c == '$' && next == '(')
                {
                    return true;
                }
            }
        }

        return false;
    }

    private enum ShellScanState
    {
        Normal,
        SingleQuote,
        DoubleQuote
    }
}

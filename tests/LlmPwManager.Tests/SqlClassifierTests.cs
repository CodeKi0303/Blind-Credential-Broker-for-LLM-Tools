using LlmPwManager.Policy;

namespace LlmPwManager.Tests;

public sealed class SqlClassifierTests
{
    [Theory]
    [InlineData("select * from users")]
    [InlineData("-- comment\nselect count(*) from users")]
    [InlineData("/* comment */ select count(*) from users")]
    [InlineData("WITH recent AS (SELECT * FROM events) SELECT count(*) FROM recent")]
    [InlineData("select 'delete from users' as sample")]
    [InlineData("select ';' as semicolon")]
    public void ReadQueriesAreNotClassifiedAsWrite(string sql)
    {
        Assert.False(SqlClassifier.IsWriteSql(sql));
        Assert.True(SqlClassifier.IsSingleReadOnlyStatement(sql));
    }

    [Theory]
    [InlineData("insert into users(id) values (1)")]
    [InlineData("UPDATE users SET name = 'x'")]
    [InlineData(" delete from users")]
    [InlineData("DROP TABLE users")]
    [InlineData("TRUNCATE TABLE users")]
    [InlineData("select * from users; delete from users")]
    [InlineData("with changed as (delete from users returning *) select * from changed")]
    public void WriteQueriesAreClassifiedAsWrite(string sql)
    {
        Assert.True(SqlClassifier.IsWriteSql(sql));
        Assert.False(SqlClassifier.IsSingleReadOnlyStatement(sql));
    }
}

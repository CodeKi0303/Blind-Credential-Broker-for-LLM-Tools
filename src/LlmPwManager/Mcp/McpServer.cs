using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace LlmPwManager.Mcp;

internal sealed class McpServer(ToolRegistry tools)
{
    private const int MaxContentLength = 10 * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    public async Task RunAsync(Stream input, Stream output, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            JsonDocument? request;
            try
            {
                request = await ReadMessageAsync(input, cancellationToken);
            }
            catch (JsonException)
            {
                await WriteMessageAsync(output, Error(null, -32700, "Parse error."), cancellationToken);
                continue;
            }
            catch (InvalidDataException)
            {
                await WriteMessageAsync(output, Error(null, -32600, "Invalid request."), cancellationToken);
                return;
            }

            if (request is null)
            {
                return;
            }

            using (request)
            {
                if (!request.RootElement.TryGetProperty("id", out var id))
                {
                    continue;
                }

                if (!request.RootElement.TryGetProperty("method", out var methodElement) ||
                    methodElement.ValueKind != JsonValueKind.String)
                {
                    await WriteMessageAsync(output, Error(id, -32600, "Invalid request."), cancellationToken);
                    continue;
                }

                var method = methodElement.GetString() ?? "";
                object response;
                try
                {
                    response = method switch
                    {
                        "initialize" => Result(id, new
                        {
                            protocolVersion = "2025-06-18",
                            capabilities = new { tools = new { } },
                            serverInfo = new { name = "llm-pw-manager", version = "0.1.0" }
                        }),
                        "tools/list" => Result(id, new { tools = tools.ListTools() }),
                        "tools/call" => Result(id, await tools.CallAsync(GetParams(request.RootElement), cancellationToken)),
                        _ => Error(id, -32601, "Method not found.")
                    };
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    response = Error(id, -32603, "Internal error.");
                }

                await WriteMessageAsync(output, response, cancellationToken);
            }
        }
    }

    private static JsonElement GetParams(JsonElement root)
    {
        return root.TryGetProperty("params", out var parameters) ? parameters : default;
    }

    private static object Result(JsonElement id, object result) => new
    {
        jsonrpc = "2.0",
        id = JsonElementToObject(id),
        result
    };

    private static object Error(JsonElement id, int code, string message) => Error(JsonElementToObject(id), code, message);

    private static object Error(object? id, int code, string message) => new
    {
        jsonrpc = "2.0",
        id,
        error = new { code, message }
    };

    private static object? JsonElementToObject(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number when element.TryGetInt64(out var number) => number,
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => element.GetRawText()
        };
    }

    private static async Task<JsonDocument?> ReadMessageAsync(Stream input, CancellationToken cancellationToken)
    {
        var headerBytes = new List<byte>();
        var buffer = new byte[1];

        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return null;
            }

            headerBytes.Add(buffer[0]);
            if (headerBytes.Count >= 4 &&
                headerBytes[^4] == '\r' &&
                headerBytes[^3] == '\n' &&
                headerBytes[^2] == '\r' &&
                headerBytes[^1] == '\n')
            {
                break;
            }
        }

        var headers = Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(headerBytes));
        var contentLength = headers
            .Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split(':', 2))
            .Where(parts => parts.Length == 2)
            .FirstOrDefault(parts => parts[0].Equals("Content-Length", StringComparison.OrdinalIgnoreCase))?[1]
            .Trim();

        if (!int.TryParse(contentLength, out var length))
        {
            throw new InvalidDataException("MCP message missing Content-Length header.");
        }

        if (length < 0 || length > MaxContentLength)
        {
            throw new InvalidDataException("MCP message Content-Length is out of range.");
        }

        var rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var offset = 0;
            while (offset < length)
            {
                var read = await input.ReadAsync(rented.AsMemory(offset, length - offset), cancellationToken);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                offset += read;
            }

            return JsonDocument.Parse(rented.AsMemory(0, length));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static async Task WriteMessageAsync(Stream output, object message, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(message, JsonOptions);
        var payload = Encoding.UTF8.GetBytes(json);
        var header = Encoding.ASCII.GetBytes($"Content-Length: {payload.Length}\r\n\r\n");
        await output.WriteAsync(header, cancellationToken);
        await output.WriteAsync(payload, cancellationToken);
        await output.FlushAsync(cancellationToken);
    }
}

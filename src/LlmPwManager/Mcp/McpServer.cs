using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace LlmPwManager.Mcp;

internal sealed class McpServer(ToolRegistry tools)
{
    private const int MaxContentLength = 10 * 1024 * 1024;
    private const string ServerInstructions =
        "Use this server when a task needs SSH, database, browser, or routed access that may require credentials. " +
        "Never ask the user to reveal passwords in chat. Call the appropriate tool; if a required credential is missing, " +
        "the broker will prompt the user outside the LLM channel, test it, and continue without exposing the secret.";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };
    private static readonly byte[] NewlineBytes = [(byte)'\n'];

    public async Task RunAsync(Stream input, Stream output, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            IncomingMessage? request;
            try
            {
                request = await ReadMessageAsync(input, cancellationToken);
            }
            catch (JsonException)
            {
                await WriteMessageAsync(output, Error(null, -32700, "Parse error."), TransportMode.ContentLength, cancellationToken);
                continue;
            }
            catch (InvalidDataException)
            {
                await WriteMessageAsync(output, Error(null, -32600, "Invalid request."), TransportMode.ContentLength, cancellationToken);
                return;
            }

            if (request is null)
            {
                return;
            }

            using (request.Document)
            {
                if (!request.Document.RootElement.TryGetProperty("id", out var id))
                {
                    continue;
                }

                if (!request.Document.RootElement.TryGetProperty("method", out var methodElement) ||
                    methodElement.ValueKind != JsonValueKind.String)
                {
                    await WriteMessageAsync(output, Error(id, -32600, "Invalid request."), request.Mode, cancellationToken);
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
                            capabilities = new
                            {
                                tools = new { },
                                resources = new { },
                                prompts = new { }
                            },
                            serverInfo = new { name = "llm-pw-manager", version = "0.1.0" },
                            instructions = ServerInstructions
                        }),
                        "resources/list" => Result(id, new { resources = Array.Empty<object>() }),
                        "resources/templates/list" => Result(id, new { resourceTemplates = Array.Empty<object>() }),
                        "prompts/list" => Result(id, new { prompts = Array.Empty<object>() }),
                        "tools/list" => Result(id, new { tools = tools.ListTools() }),
                        "tools/call" => Result(id, await tools.CallAsync(GetParams(request.Document.RootElement), cancellationToken)),
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

                await WriteMessageAsync(output, response, request.Mode, cancellationToken);
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

    private static async Task<IncomingMessage?> ReadMessageAsync(Stream input, CancellationToken cancellationToken)
    {
        var firstByte = await ReadFirstMessageByteAsync(input, cancellationToken);
        if (firstByte is null)
        {
            return null;
        }

        if (firstByte is (byte)'{' or (byte)'[')
        {
            return new IncomingMessage(
                await ReadNewlineDelimitedMessageAsync(input, firstByte.Value, cancellationToken),
                TransportMode.NewlineDelimited);
        }

        var headerBytes = new List<byte>();
        headerBytes.Add(firstByte.Value);
        var buffer = new byte[1];

        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return null;
            }

            headerBytes.Add(buffer[0]);
            if (HeaderIsComplete(headerBytes))
            {
                break;
            }
        }

        var headers = Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(headerBytes));
        var contentLength = headers
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.TrimEnd('\r'))
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

            return new IncomingMessage(
                JsonDocument.Parse(rented.AsMemory(0, length)),
                TransportMode.ContentLength);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static async Task<byte?> ReadFirstMessageByteAsync(Stream input, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return null;
            }

            if (buffer[0] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            {
                continue;
            }

            return buffer[0];
        }
    }

    private static async Task<JsonDocument> ReadNewlineDelimitedMessageAsync(
        Stream input,
        byte firstByte,
        CancellationToken cancellationToken)
    {
        var bytes = new List<byte> { firstByte };
        var buffer = new byte[1];

        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            if (buffer[0] == '\n')
            {
                break;
            }

            if (bytes.Count >= MaxContentLength)
            {
                throw new InvalidDataException("MCP message Content-Length is out of range.");
            }

            bytes.Add(buffer[0]);
        }

        if (bytes.Count > 0 && bytes[^1] == '\r')
        {
            bytes.RemoveAt(bytes.Count - 1);
        }

        return JsonDocument.Parse(bytes.ToArray());
    }

    private static bool HeaderIsComplete(List<byte> headerBytes)
    {
        if (headerBytes.Count >= 4 &&
            headerBytes[^4] == '\r' &&
            headerBytes[^3] == '\n' &&
            headerBytes[^2] == '\r' &&
            headerBytes[^1] == '\n')
        {
            return true;
        }

        return headerBytes.Count >= 2 &&
            headerBytes[^2] == '\n' &&
            headerBytes[^1] == '\n';
    }

    private static async Task WriteMessageAsync(
        Stream output,
        object message,
        TransportMode mode,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(message, JsonOptions);
        var payload = Encoding.UTF8.GetBytes(json);
        if (mode == TransportMode.NewlineDelimited)
        {
            await output.WriteAsync(payload, cancellationToken);
            await output.WriteAsync(NewlineBytes, cancellationToken);
            await output.FlushAsync(cancellationToken);
            return;
        }

        var header = Encoding.ASCII.GetBytes($"Content-Length: {payload.Length}\r\n\r\n");
        await output.WriteAsync(header, cancellationToken);
        await output.WriteAsync(payload, cancellationToken);
        await output.FlushAsync(cancellationToken);
    }

    private sealed record IncomingMessage(JsonDocument Document, TransportMode Mode);

    private enum TransportMode
    {
        ContentLength,
        NewlineDelimited
    }
}

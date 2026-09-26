using System.Diagnostics;
using System.Globalization;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http.Http1;

internal sealed class Http1Connection : IHttpConnection
{
    /// <summary>Bodies up to this size go out in the same write as the head, i.e. one TLS record, like OkHttp's buffered sink.</summary>
    private const int CoalesceLimit = 16 * 1024;

    private readonly HttpReadStream _stream;
    private readonly Action<Http1Connection> _release;
    private long _idleSince = Stopwatch.GetTimestamp();
    private bool _canReuse = true;
    private int _disposed;

    public Http1Connection(Origin origin, ClientProfile profile, Stream stream, Action<Http1Connection> release)
    {
        Origin = origin;
        Profile = profile;
        _stream = new HttpReadStream(stream);
        _release = release;
    }

    public Origin Origin { get; }

    public ClientProfile Profile { get; }

    public bool IsReusable => _canReuse && Volatile.Read(ref _disposed) == 0;

    public bool WasReused { get; private set; }

    public TimeSpan IdleTime => Stopwatch.GetElapsedTime(_idleSince);

    public void MarkIdle() => _idleSince = Stopwatch.GetTimestamp();

    public void MarkReused() => WasReused = true;

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, RequestKind kind, string? cookieHeader, CancellationToken cancellationToken)
    {
        RequestHeaderPlan plan;
        byte[] head;
        try
        {
            plan = RequestHeaderBuilder.Build(request, Profile, kind, cookieHeader);
            head = Http1RequestHead.Encode(request.Method.Method, request.RequestUri!.PathAndQuery, plan.Headers);
        }
        catch
        {
            // Nothing was written; the connection is still clean.
            _release(this);
            throw;
        }

        _canReuse &= !plan.CloseRequested;
        var headReceived = false;
        try
        {
            Http1ResponseHead response;
            await using (cancellationToken.Register(static state => ((Http1Connection)state!).Abort(), this).ConfigureAwait(false))
            {
                await WriteRequestAsync(request.Content, plan, head, cancellationToken).ConfigureAwait(false);
                do
                {
                    response = await _stream.ReadResponseHeadAsync(cancellationToken).ConfigureAwait(false);
                }
                while (response.StatusCode is >= 100 and < 200 and not 101);

                headReceived = true;
            }

            return CreateResponse(request, response, plan.TransparentDecompression);
        }
        catch (Exception exception) when (cancellationToken.IsCancellationRequested && exception is not OperationCanceledException)
        {
            Abort();
            throw new OperationCanceledException("The request was canceled.", exception, cancellationToken);
        }
        catch (IOException exception) when (WasReused && !headReceived && request.Content is null)
        {
            Abort();
            throw new StaleConnectionException(exception);
        }
        catch (IOException exception)
        {
            Abort();
            throw new HttpRequestException(
                exception is HttpIOException http ? http.HttpRequestError : HttpRequestError.Unknown,
                $"The HTTP/1.1 exchange with {Origin.Host} failed.",
                exception);
        }
        catch
        {
            Abort();
            throw;
        }
    }

    /// <summary>Called once per response by its body stream (or directly when there is no body).</summary>
    public void BodyFinished(bool reusable)
    {
        if (reusable && IsReusable)
        {
            _release(this);
        }
        else
        {
            Dispose();
        }
    }

    public void Abort() => Dispose();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _stream.Dispose();
        }
    }

    private async Task WriteRequestAsync(HttpContent? content, RequestHeaderPlan plan, byte[] head, CancellationToken cancellationToken)
    {
        if (content is null)
        {
            await _stream.WriteAsync(head, cancellationToken).ConfigureAwait(false);
        }
        else if (plan.ContentLength is <= CoalesceLimit and var length)
        {
            var body = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (body.Length != length)
            {
                throw new HttpRequestException(HttpRequestError.Unknown, "The request content length does not match its Content-Length.");
            }

            await _stream.WriteAsync((byte[])[.. head, .. body], cancellationToken).ConfigureAwait(false);
        }
        else if (plan.ContentLength is { } longLength)
        {
            await _stream.WriteAsync(head, cancellationToken).ConfigureAwait(false);
            var body = new ContentLengthRequestBodyStream(_stream, longLength);
            await content.CopyToAsync(body, cancellationToken).ConfigureAwait(false);
            body.EnsureComplete();
        }
        else
        {
            await _stream.WriteAsync(head, cancellationToken).ConfigureAwait(false);
            var body = new ChunkedRequestBodyStream(_stream);
            await content.CopyToAsync(body, cancellationToken).ConfigureAwait(false);
            await body.CompleteAsync(cancellationToken).ConfigureAwait(false);
        }

        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private HttpResponseMessage CreateResponse(HttpRequestMessage request, Http1ResponseHead head, bool transparentDecompression)
    {
        _canReuse &= !head.HasToken("Connection", "close") && (head.Version.Minor >= 1 || head.HasToken("Connection", "keep-alive"));

        var body = OpenBody(request, head);
        var response = ResponseFactory.Create(request, head.StatusCode, head.Version, head.ReasonPhrase, head.Headers, body, transparentDecompression);
        if (body is null)
        {
            BodyFinished(reusable: head.StatusCode != 101);
        }

        return response;
    }

    private Http1BodyStream? OpenBody(HttpRequestMessage request, Http1ResponseHead head)
    {
        if (request.Method == HttpMethod.Head || head.StatusCode is < 200 or 204 or 304)
        {
            return null;
        }

        var transferCodings = head.GetValues("Transfer-Encoding")
            .SelectMany(static value => value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .ToList();
        if (transferCodings.Count > 0)
        {
            // RFC 9112 §6.3: Transfer-Encoding wins over Content-Length; a non-chunked final coding means close-delimited.
            return string.Equals(transferCodings[^1], "chunked", StringComparison.OrdinalIgnoreCase)
                ? new ChunkedBodyStream(this, _stream)
                : new CloseDelimitedBodyStream(this, _stream);
        }

        var lengths = head.GetValues("Content-Length")
            .SelectMany(static value => value.Split(',', StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (lengths.Count == 0)
        {
            return new CloseDelimitedBodyStream(this, _stream);
        }

        if (lengths.Count > 1 || !long.TryParse(lengths[0], NumberStyles.None, CultureInfo.InvariantCulture, out var length))
        {
            throw new HttpIOException(HttpRequestError.InvalidResponse, $"Invalid Content-Length '{string.Join(", ", lengths)}'.");
        }

        return length == 0 ? null : new ContentLengthBodyStream(this, _stream, length);
    }
}

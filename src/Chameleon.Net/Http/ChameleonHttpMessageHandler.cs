using System.Net;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Security;

namespace Chameleon.Net.Http;

/// <summary><see cref="HttpMessageHandler"/> whose connections look like the profile's client: TLS ClientHello, ALPN, HTTP/2 preface and
/// framing, header order and casing, default headers.
/// <code>using var client = new HttpClient(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13));</code>
/// For https the profile's ALPN offer decides between HTTP/2 and HTTP/1.1, whatever <see cref="HttpRequestMessage.Version"/> says —
/// the real client doesn't let the caller choose either. Plain http uses HTTP/1.1, or HTTP/2 with prior knowledge when the request
/// asks for exactly version 2.0.</summary>
public sealed class ChameleonHttpMessageHandler : HttpMessageHandler
{
    private const int MaxAttempts = 5;
    private const int MaxRefusedStreamAttempts = 20;

    private readonly ConnectionPool _pool;
    private readonly bool _allowAutoRedirect;
    private readonly int _maxAutomaticRedirections;
    private readonly CookieContainer? _cookies;
    private readonly ILogger _logger;
    private volatile bool _disposed;

    public ChameleonHttpMessageHandler(ClientProfile profile, ChameleonOptions? options = null)
        : this(options ?? new ChameleonOptions(), SingleProfile(profile, options))
    {
    }

    public ChameleonHttpMessageHandler(ChameleonOptions options)
        : this(options, ProfileSelectorOf(options))
    {
    }

    private ChameleonHttpMessageHandler(ChameleonOptions options, IProfileSelector profileSelector)
    {
        if (options.TcpFingerprintApplicator is not null)
        {
            throw new NotSupportedException("TcpFingerprintApplicator is not supported yet.");
        }

        ProxyRouting.Validate(options.Proxy);

        if (options.ConnectTimeout <= TimeSpan.Zero && options.ConnectTimeout != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ConnectTimeout, "ConnectTimeout must be positive or infinite.");
        }

        if (options.AllowAutoRedirect && options.MaxAutomaticRedirections <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.MaxAutomaticRedirections, "MaxAutomaticRedirections must be positive.");
        }

        var random = new SecureRandom();
        var tls = new BouncyCastleTlsConnectionFactory(
            new ProfileTlsClientFactory(),
            new ClientHelloEncoder(random),
            options.CertificateValidator ?? new SystemCertificateValidator(),
            random)
        {
            ResumeSessions = options.TlsSessionResumption,
            SessionCache = options.TlsSessionCache ?? new TlsSessionCache(),
        };

        _logger = options.LoggerFactory?.CreateLogger(Log.Category) ?? NullLogger.Instance;
        _pool = new ConnectionPool(profileSelector, tls, new ProxyRouting(new TcpTransport(), options.Proxy), options.ConnectTimeout, _logger);
        _allowAutoRedirect = options.AllowAutoRedirect;
        _maxAutomaticRedirections = options.MaxAutomaticRedirections;
        _cookies = options.Cookies;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var kind = request.Options.TryGetValue(ChameleonRequestOptions.Kind, out var requestKind) ? requestKind : RequestKind.Fetch;
        var response = await SendOnceAsync(request, kind, cancellationToken).ConfigureAwait(false);

        for (var redirects = 0; _allowAutoRedirect && redirects < _maxAutomaticRedirections; redirects++)
        {
            if (RedirectTarget(request, response) is not { } target)
            {
                break;
            }

            response.Dispose();
            Log.Redirecting(_logger, (int)response.StatusCode, target);
            PrepareRedirect(request, response.StatusCode, target);
            response = await SendOnceAsync(request, kind, cancellationToken).ConfigureAwait(false);
        }

        return response;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            _pool.Dispose();
        }

        base.Dispose(disposing);
    }

    private async Task<HttpResponseMessage> SendOnceAsync(HttpRequestMessage request, RequestKind kind, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri;
        if (uri is null || !uri.IsAbsoluteUri)
        {
            throw new InvalidOperationException("The request URI must be absolute.");
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            throw new NotSupportedException($"The '{uri.Scheme}' scheme is not supported.");
        }

        var origin = new Origin(uri.Scheme, HttpUris.ConnectHost(uri), HttpUris.Port(uri));
        var cookieHeader = _cookies is not null && !request.Headers.Contains("Cookie") ? _cookies.GetCookieHeader(uri) : null;
        var http2PriorKnowledge = uri.Scheme == "http" && request.Version.Major >= 2 && request.VersionPolicy == HttpVersionPolicy.RequestVersionExact;

        HttpResponseMessage response;
        var refusals = 0;
        for (var attempt = 1; ; attempt++)
        {
            var connection = await _pool.RentAsync(origin, http2PriorKnowledge, cancellationToken).ConfigureAwait(false);
            try
            {
                response = await connection.SendAsync(request, kind, cookieHeader, cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (StaleConnectionException exception)
            {
                // The server provably didn't process the request (closed pooled connection, GOAWAY, REFUSED_STREAM): replay it.
                // Refused streams get their own, larger budget and a short pause: a server at its stream limit (Kestrel counts a
                // stream until its app pipeline returns, a moment after END_STREAM) frees a slot soon. SocketsHttpHandler retries
                // them without limit.
                var refused = exception.InnerException is Http2.Http2RetryableException { RefusedStream: true };
                if (refused ? ++refusals == MaxRefusedStreamAttempts : attempt - refusals == MaxAttempts)
                {
                    throw new HttpRequestException(HttpRequestError.Unknown, $"{origin.Host} kept refusing the request.", exception.InnerException);
                }

                Log.Replaying(_logger, request.Method.Method, uri, exception.InnerException?.Message ?? exception.Message);
                if (refused)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(refusals * 5), cancellationToken).ConfigureAwait(false);
                }
            }
        }

        StoreCookies(uri, response);
        return response;
    }

    private void StoreCookies(Uri uri, HttpResponseMessage response)
    {
        if (_cookies is null || !response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }

        foreach (var value in values)
        {
            try
            {
                _cookies.SetCookies(uri, value);
            }
            catch (CookieException)
            {
                // Malformed cookies are dropped, as browsers do.
            }
        }
    }

    private static Uri? RedirectTarget(HttpRequestMessage request, HttpResponseMessage response)
    {
        if (response.StatusCode is not (HttpStatusCode.MultipleChoices or HttpStatusCode.MovedPermanently or HttpStatusCode.Found
                or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
            || response.Headers.Location is not { } location)
        {
            return null;
        }

        var target = location.IsAbsoluteUri ? location : new Uri(request.RequestUri!, location);
        var downgrade = request.RequestUri!.Scheme == "https" && target.Scheme == "http";
        return target.Scheme is "http" or "https" && !downgrade ? target : null;
    }

    private static void PrepareRedirect(HttpRequestMessage request, HttpStatusCode status, Uri target)
    {
        request.RequestUri = target;

        var becomesGet = status switch
        {
            HttpStatusCode.MultipleChoices or HttpStatusCode.MovedPermanently or HttpStatusCode.Found => request.Method == HttpMethod.Post,
            HttpStatusCode.SeeOther => request.Method != HttpMethod.Head,
            _ => false,
        };
        if (becomesGet)
        {
            request.Method = HttpMethod.Get;
            request.Content = null;
        }

        request.Headers.Authorization = null;
    }

    private static FixedProfileSelector SingleProfile(ClientProfile profile, ChameleonOptions? options)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (options?.ProfileSelector is not null)
        {
            throw new ArgumentException("Pass either a profile or options.ProfileSelector, not both.", nameof(options));
        }

        return new FixedProfileSelector(profile);
    }

    private static IProfileSelector ProfileSelectorOf(ChameleonOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.ProfileSelector ?? throw new ArgumentException("options.ProfileSelector must be set.", nameof(options));
    }
}

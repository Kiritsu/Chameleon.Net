using Chameleon.Net;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.WebSockets;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Chameleon.Net for <c>IHttpClientFactory</c> and dependency injection.</summary>
/// <remarks>Everything registered here shares one <see cref="TlsSessionCache"/> (unless the options set their own), so a WebSocket
/// connection resumes the TLS session of earlier HTTP requests to the same host, as one OkHttpClient does for both. Tickets stay
/// apart per profile and per certificate validator, so sharing never links different profiles. Logging uses the container's
/// <see cref="ILoggerFactory"/>.</remarks>
public static class ChameleonServiceCollectionExtensions
{
    /// <summary>Makes <see cref="ChameleonHttpMessageHandler"/> this client's primary handler, with one profile for every connection.</summary>
    /// <param name="configure">Further options (proxy, cookies, timeouts...); setting <see cref="ChameleonOptions.ProfileSelector"/> here
    /// replaces <paramref name="profile"/>.</param>
    public static IHttpClientBuilder UseChameleon(this IHttpClientBuilder builder, ClientProfile profile, Action<ChameleonOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(profile);

        return builder.UseChameleon((_, options) =>
        {
            options.ProfileSelector = new FixedProfileSelector(profile);
            configure?.Invoke(options);
        });
    }

    /// <summary>Makes <see cref="ChameleonHttpMessageHandler"/> this client's primary handler, configured from the container.
    /// <paramref name="configure"/> must set <see cref="ChameleonOptions.ProfileSelector"/>.</summary>
    /// <remarks>Also sets the handler lifetime to infinite. The handler already does what IHttpClientFactory's handler rotation is for
    /// (it closes idle connections, like OkHttp's pool), and rotating it every two minutes would drop its pooled connections, TLS
    /// session tickets and cookies, which the real clients keep. Call <c>SetHandlerLifetime</c> afterwards to change that.</remarks>
    public static IHttpClientBuilder UseChameleon(this IHttpClientBuilder builder, Action<IServiceProvider, ChameleonOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.TryAddSingleton<TlsSessionCache>();
        builder.ConfigurePrimaryHttpMessageHandler(services =>
        {
            var options = CreateOptions(services);
            configure(services, options);
            if (options.ProfileSelector is null)
            {
                throw new InvalidOperationException($"UseChameleon needs a profile: pass one, or set {nameof(ChameleonOptions.ProfileSelector)} in the configure callback.");
            }

            return new ChameleonHttpMessageHandler(options);
        });
        builder.SetHandlerLifetime(Timeout.InfiniteTimeSpan);
        return builder;
    }

    /// <summary>Registers a singleton <see cref="ChameleonWebSocketConnector"/>, also as <see cref="IWebSocketConnector"/>.</summary>
    public static IServiceCollection AddChameleonWebSocketConnector(this IServiceCollection services, Action<ChameleonOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.AddChameleonWebSocketConnector((_, options) => configure?.Invoke(options));
    }

    /// <summary>Registers a singleton <see cref="ChameleonWebSocketConnector"/>, also as <see cref="IWebSocketConnector"/>, configured from the container.</summary>
    public static IServiceCollection AddChameleonWebSocketConnector(this IServiceCollection services, Action<IServiceProvider, ChameleonOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.TryAddSingleton<TlsSessionCache>();
        services.TryAddSingleton(provider =>
        {
            var options = CreateOptions(provider);
            configure(provider, options);
            return new ChameleonWebSocketConnector(options);
        });
        services.TryAddSingleton<IWebSocketConnector>(static provider => provider.GetRequiredService<ChameleonWebSocketConnector>());
        return services;
    }

    private static ChameleonOptions CreateOptions(IServiceProvider services) => new()
    {
        LoggerFactory = services.GetService<ILoggerFactory>(),
        TlsSessionCache = services.GetRequiredService<TlsSessionCache>(),
    };
}

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net.Tests.Support;

/// <summary>Keeps every formatted log message.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Queue { get; } = new();

    public IReadOnlyCollection<string> Messages => [.. Queue];

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(Queue);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            messages.Enqueue(formatter(state, exception));
    }
}

using DecisionsFramework.Utilities.Logging;
using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;
using Serilog.Formatting.Json;
using Serilog.Sinks.PeriodicBatching;

namespace Decisions.Zitac.AWS.Logging
{
    /// <summary>
    /// Registered through the ISinkConfiguration path (like the built-in Windows Event sink), not
    /// ISerilogSinkProvider: Decisions calls Configure() at startup and again every time these sink
    /// settings are saved, and only calls ConfigureSink when the sink is enabled. The provider path
    /// used by the built-in AWS sink is only evaluated at startup, so changes needed a restart.
    /// </summary>
    public class AWSCloudWatchSerilogSink : AbstractSinkConfiguration<AWSCloudWatchLoggingSettings>
    {
        public override LoggerConfiguration ConfigureSink(LoggerSinkConfiguration configure)
        {
            // An exception here would propagate out of DecisionsLoggingConfiguration.Configure(), which
            // Log.Initialize rethrows during boot. Logging to CloudWatch must never be able to stop the server.
            try
            {
                return ConfigureCloudWatchSink(configure);
            }
            catch (Exception ex)
            {
                SelfLog.WriteLine("Zitac AWS CloudWatch sink could not be configured and is disabled: {0}", ex);
                return null;
            }
        }

        private LoggerConfiguration ConfigureCloudWatchSink(LoggerSinkConfiguration configure)
        {
            AWSCloudWatchLoggingSettings settings = SinkSettings;
            var groupResolver = new LogGroupResolver(settings.LogGroupPath, GetProcessName(), settings.RouteByProject);
            var cloudWatchSink = new CloudWatchLogsBatchedSink(() => SinkSettings.GetConnection(), groupResolver, new JsonFormatter());

            ILogEventSink sink = new PeriodicBatchingSink(cloudWatchSink, new PeriodicBatchingSinkOptions
            {
                BatchSizeLimit = 1000,
                Period = TimeSpan.FromSeconds(10),
                QueueLimit = 10000,
                EagerlyEmitFirstEvent = true
            });

            // Runs on the logging thread, where the running flow is still known (see FlowContextSink).
            sink = new FlowContextSink(sink);

            // Filtered before queueing, so other logs never take up queue space.
            if (settings.OnlyLogSteps)
                sink = new FilteringSink(sink, LogGroupResolver.IsFromLogStep);

            return configure.Sink(sink);
        }

        /// <summary>
        /// The process name, e.g. "Decisions.Web.Core". Only a real ".dll"/".exe" extension is removed:
        /// Path.GetFileNameWithoutExtension (used by Decisions' own naming) would cut it to "Decisions.Web".
        /// </summary>
        private static string GetProcessName()
        {
            string name = AppDomain.CurrentDomain.FriendlyName;
            if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                name = name.Substring(0, name.Length - 4);
            return name;
        }

        private sealed class FilteringSink : ILogEventSink, IDisposable
        {
            private readonly ILogEventSink inner;
            private readonly Func<LogEvent, bool> include;

            public FilteringSink(ILogEventSink inner, Func<LogEvent, bool> include)
            {
                this.inner = inner;
                this.include = include;
            }

            public void Emit(LogEvent logEvent)
            {
                if (include(logEvent))
                    inner.Emit(logEvent);
            }

            // Flushes the batching sink's queue when Decisions disposes the logger (settings save, shutdown).
            public void Dispose()
            {
                (inner as IDisposable)?.Dispose();
            }
        }
    }
}

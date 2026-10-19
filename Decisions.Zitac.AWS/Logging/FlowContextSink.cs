using DecisionsFramework.Design.Flow;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace Decisions.Zitac.AWS.Logging
{
    /// <summary>
    /// Adds TopFlowTrackingId, FlowTrackingId and FlowName to entries written from inside a running flow,
    /// so a whole execution (including synchronous subflows) can be followed in CloudWatch.
    ///
    /// Emit runs synchronously on the thread that wrote the log entry (Decisions' own enrichers depend on
    /// the same thing), and FlowEngine keeps the running engine in a [ThreadStatic] field, so the context
    /// must be captured here, before the entry is queued for the background sender.
    /// Decisions passes one LogEvent instance to every sink, so the event is copied, never modified:
    /// the fields only appear in CloudWatch, not in the log file or other sinks.
    /// </summary>
    internal sealed class FlowContextSink : ILogEventSink, IDisposable
    {
        public const string TOP_FLOW_TRACKING_ID = "TopFlowTrackingId";
        public const string FLOW_TRACKING_ID = "FlowTrackingId";
        public const string FLOW_NAME = "FlowName";

        private readonly ILogEventSink inner;

        public FlowContextSink(ILogEventSink inner)
        {
            this.inner = inner;
        }

        public void Emit(LogEvent logEvent)
        {
            inner.Emit(AddFlowContext(logEvent));
        }

        private static LogEvent AddFlowContext(LogEvent logEvent)
        {
            try
            {
                // Only while the engine is running: a few FlowEngine code paths set the thread's engine
                // without restoring it, so a stale engine on a reused thread must not stamp its ids.
                FlowEngine engine = FlowEngine.GetCurrentEngine(false);
                if (engine == null || !engine.IsRunning())
                    return logEvent;

                string flowTrackingId = engine.FlowTrackingID;
                if (string.IsNullOrEmpty(flowTrackingId))
                    return logEvent;

                var properties = logEvent.Properties
                    .Select(p => new LogEventProperty(p.Key, p.Value))
                    .ToList();
                AddIfMissing(properties, logEvent, TOP_FLOW_TRACKING_ID, FlowEngine.GetTopFlowTrackingId(flowTrackingId));
                AddIfMissing(properties, logEvent, FLOW_TRACKING_ID, flowTrackingId);
                AddIfMissing(properties, logEvent, FLOW_NAME, FlowEngine.CurrentFlow?.Name);

                return new LogEvent(logEvent.Timestamp, logEvent.Level, logEvent.Exception, logEvent.MessageTemplate, properties);
            }
            catch (Exception ex)
            {
                // Never lose the entry because the flow context couldn't be read.
                SelfLog.WriteLine("Zitac AWS CloudWatch: could not add flow context: {0}", ex.Message);
                return logEvent;
            }
        }

        private static void AddIfMissing(List<LogEventProperty> properties, LogEvent logEvent, string name, string value)
        {
            if (!string.IsNullOrEmpty(value) && !logEvent.Properties.ContainsKey(name))
                properties.Add(new LogEventProperty(name, new ScalarValue(value)));
        }

        public void Dispose()
        {
            (inner as IDisposable)?.Dispose();
        }
    }
}

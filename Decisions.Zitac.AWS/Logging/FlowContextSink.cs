using DecisionsFramework.Design.Flow;
using DecisionsFramework.ServiceLayer.Utilities;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace Decisions.Zitac.AWS.Logging
{
    /// <summary>
    /// Adds context to CloudWatch entries:
    /// - Account: email of the account the work runs as (any entry with a user context);
    /// - TopFlowTrackingId, FlowTrackingId, FlowName: for entries written from inside a running flow, so a
    ///   whole execution (including synchronous subflows) can be followed.
    ///
    /// Emit runs synchronously on the thread that wrote the log entry (Decisions' own enrichers depend on
    /// the same thing). FlowEngine keeps the running engine in a [ThreadStatic] field and the user context is
    /// async-local, so the context must be captured here, before the entry is queued for the background sender.
    /// Decisions passes one LogEvent instance to every sink, so the event is copied, never modified:
    /// the fields only appear in CloudWatch, not in the log file or other sinks.
    /// </summary>
    internal sealed class FlowContextSink : ILogEventSink, IDisposable
    {
        public const string ACCOUNT = "Account";
        public const string TOP_FLOW_TRACKING_ID = "TopFlowTrackingId";
        public const string FLOW_TRACKING_ID = "FlowTrackingId";
        public const string FLOW_NAME = "FlowName";

        // Loading an account the first time can itself write log entries, which come straight back here.
        [ThreadStatic]
        private static bool resolvingAccount;

        private readonly ILogEventSink inner;

        public FlowContextSink(ILogEventSink inner)
        {
            this.inner = inner;
        }

        public void Emit(LogEvent logEvent)
        {
            inner.Emit(AddContext(logEvent));
        }

        private static LogEvent AddContext(LogEvent logEvent)
        {
            var added = new List<LogEventProperty>();

            AddIfMissing(added, logEvent, ACCOUNT, GetAccountEmail());

            try
            {
                // Only while the engine is running: a few FlowEngine code paths set the thread's engine
                // without restoring it, so a stale engine on a reused thread must not stamp its ids.
                FlowEngine engine = FlowEngine.GetCurrentEngine(false);
                string flowTrackingId = engine != null && engine.IsRunning() ? engine.FlowTrackingID : null;
                if (!string.IsNullOrEmpty(flowTrackingId))
                {
                    AddIfMissing(added, logEvent, TOP_FLOW_TRACKING_ID, FlowEngine.GetTopFlowTrackingId(flowTrackingId));
                    AddIfMissing(added, logEvent, FLOW_TRACKING_ID, flowTrackingId);
                    AddIfMissing(added, logEvent, FLOW_NAME, FlowEngine.CurrentFlow?.Name);
                }
            }
            catch (Exception ex)
            {
                // Never lose the entry because the flow context couldn't be read.
                SelfLog.WriteLine("Zitac AWS CloudWatch: could not add flow context: {0}", ex.Message);
            }

            if (added.Count == 0)
                return logEvent;

            var properties = logEvent.Properties
                .Select(p => new LogEventProperty(p.Key, p.Value))
                .Concat(added);
            return new LogEvent(logEvent.Timestamp, logEvent.Level, logEvent.Exception, logEvent.MessageTemplate, properties);
        }

        /// <summary>
        /// Usually just a field read: the user context caches its account after the first GetAccount(),
        /// which running a flow normally has already done. Otherwise Decisions loads it once (from its
        /// account cache or the database) and keeps it for the rest of the request.
        /// </summary>
        private static string GetAccountEmail()
        {
            if (resolvingAccount)
                return null;
            try
            {
                resolvingAccount = true;
                return UserContextHolder.GetCurrent()?.GetAccount()?.EmailAddress;
            }
            catch
            {
                // e.g. an expired or invalid session: leave the field out.
                return null;
            }
            finally
            {
                resolvingAccount = false;
            }
        }

        private static void AddIfMissing(List<LogEventProperty> added, LogEvent logEvent, string name, string value)
        {
            if (!string.IsNullOrEmpty(value) && !logEvent.Properties.ContainsKey(name))
                added.Add(new LogEventProperty(name, new ScalarValue(value)));
        }

        public void Dispose()
        {
            (inner as IDisposable)?.Dispose();
        }
    }
}

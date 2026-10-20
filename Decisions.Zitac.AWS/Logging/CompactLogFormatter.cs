using System.Text.Encodings.Web;
using System.Text.Json;
using Serilog.Events;
using Serilog.Formatting;

namespace Decisions.Zitac.AWS.Logging
{
    /// <summary>
    /// Flat JSON with only the fields useful for following flows, e.g.
    /// {"Level":"Information","Message":"...","Category":"ERS","Account":"user@example.com","FlowName":"Send","TopFlowTrackingId":"..."}.
    /// Leaves out Decisions' diagnostic enrichments (LogNumber, ThreadId, node and session fields) and the
    /// Timestamp, which CloudWatch stores with every event anyway. Activity (the step history Decisions
    /// attaches to Error/Fatal entries) is only kept for those levels.
    /// </summary>
    public class CompactLogFormatter : ITextFormatter
    {
        private static readonly string[] KEPT_PROPERTIES =
        {
            "Category",
            FlowContextSink.ACCOUNT,
            FlowContextSink.FLOW_NAME,
            FlowContextSink.TOP_FLOW_TRACKING_ID,
            FlowContextSink.FLOW_TRACKING_ID,
            LogGroupResolver.FLOW_ID_PROPERTY
        };

        private static readonly JsonSerializerOptions jsonOptions = new JsonSerializerOptions
        {
            // Keep e.g. "®", "å" and quotes readable instead of \u escapes; still valid JSON.
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        public void Format(LogEvent logEvent, TextWriter output)
        {
            var entry = new Dictionary<string, string>
            {
                ["Level"] = logEvent.Level.ToString(),
                ["Message"] = logEvent.MessageTemplate.Text
            };

            foreach (string name in KEPT_PROPERTIES)
            {
                string value = GetScalar(logEvent, name);
                if (!string.IsNullOrEmpty(value) && value != "Not Available")
                    entry[name] = value;
            }

            if (logEvent.Exception != null)
                entry["Exception"] = logEvent.Exception.ToString();

            if (logEvent.Level >= LogEventLevel.Error)
            {
                string activity = GetScalar(logEvent, "Activity");
                if (!string.IsNullOrEmpty(activity))
                    entry["Activity"] = activity;
            }

            output.Write(JsonSerializer.Serialize(entry, jsonOptions));
        }

        private static string GetScalar(LogEvent logEvent, string name)
        {
            return logEvent.Properties.TryGetValue(name, out LogEventPropertyValue value) && value is ScalarValue scalar
                ? scalar.Value?.ToString()
                : null;
        }
    }
}

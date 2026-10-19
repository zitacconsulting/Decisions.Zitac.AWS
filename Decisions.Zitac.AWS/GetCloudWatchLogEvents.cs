using System.Text.Json;
using Amazon.Runtime;
using Decisions.Zitac.AWS.Authentication;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.Mapping.InputImpl;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.Properties.Attributes;

namespace Decisions.Zitac.AWS.Steps
{
    /// <summary>
    /// Reads log events with CloudWatch Logs FilterLogEvents: filter pattern, time range, and real paging
    /// through nextToken. CloudWatch always returns events oldest first.
    /// https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html
    /// </summary>
    [AutoRegisterStep("Get CloudWatch Log Events", "Integration", "AWS", "Zitac")]
    [Writable]
    public class GetCloudWatchLogEvents : BaseAwsStep, IDefaultInputMappingStep
    {
        private const string INPUT_LOG_GROUP = "Log Group Name";
        private const string INPUT_START = "Start Time";
        private const string INPUT_END = "End Time";
        private const string INPUT_FILTER = "Filter Pattern";
        private const string INPUT_STREAM_PREFIX = "Log Stream Name Prefix";
        private const string INPUT_PAGE_SIZE = "Page Size";
        private const string INPUT_PAGE_TOKEN = "Page Token";
        private const string OUTPUT_EVENTS = "Events";
        private const string OUTPUT_NEXT_TOKEN = "Next Page Token";
        private const string OUTPUT_HAS_MORE = "Has More Pages";

        private const int DEFAULT_PAGE_SIZE = 100;
        private const int MAX_PAGE_SIZE = 10000;
        private const int DEFAULT_MINUTES_BACK = 60;

        // FilterLogEvents may return fewer events than asked for, even none, while there are more: it searches
        // a slice of the log streams per call. Keep calling (within limits) so a page is usually full.
        private const int MAX_CALLS_PER_PAGE = 20;
        private static readonly TimeSpan PAGE_TIME_BUDGET = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan DELAY_BETWEEN_CALLS = TimeSpan.FromMilliseconds(200);

        [PropertyClassification(new[] { INPUTS_CATEGORY }, "Log Events Info", 0)]
        [InfoOrWarningEditor(false, "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html", true)]
        public string InputsNote
        {
            get { return "Oldest first. Ignored times = last 60 minutes. Filter example: { $.Level = \"Error\" }. Pass Next Page Token to get the next page."; }
            set { }
        }

        protected override IEnumerable<DataDescription> StepInputs => new[]
        {
            new DataDescription(typeof(string), INPUT_LOG_GROUP),
            new DataDescription(typeof(DateTime), INPUT_START),
            new DataDescription(typeof(DateTime), INPUT_END),
            new DataDescription(typeof(string), INPUT_FILTER),
            new DataDescription(typeof(string), INPUT_STREAM_PREFIX),
            new DataDescription(typeof(int), INPUT_PAGE_SIZE),
            new DataDescription(typeof(string), INPUT_PAGE_TOKEN)
        };

        public IInputMapping[] DefaultInputs => new IInputMapping[]
        {
            new IgnoreInputMapping { InputDataName = INPUT_START },
            new IgnoreInputMapping { InputDataName = INPUT_END },
            new IgnoreInputMapping { InputDataName = INPUT_FILTER },
            new IgnoreInputMapping { InputDataName = INPUT_STREAM_PREFIX },
            new ConstantInputMapping { InputDataName = INPUT_PAGE_SIZE, Value = DEFAULT_PAGE_SIZE },
            new IgnoreInputMapping { InputDataName = INPUT_PAGE_TOKEN }
        };

        protected override DataDescription[] DoneOutputs => new[]
        {
            new DataDescription(typeof(CloudWatchLogEvent), OUTPUT_EVENTS, true),
            new DataDescription(typeof(string), OUTPUT_NEXT_TOKEN),
            new DataDescription(typeof(bool), OUTPUT_HAS_MORE)
        };

        protected override Dictionary<string, object> RunStep(StepStartData data, AwsConnection connection)
        {
            string logGroupName = (data.Data[INPUT_LOG_GROUP] as string)?.Trim();
            if (string.IsNullOrEmpty(logGroupName))
                throw new ArgumentException("Log Group Name is required, e.g. /decisions/Decisions.Web.Core");

            DateTime end = AsUtc(data.Data[INPUT_END] as DateTime?) ?? DateTime.UtcNow;
            DateTime start = AsUtc(data.Data[INPUT_START] as DateTime?) ?? end.AddMinutes(-DEFAULT_MINUTES_BACK);
            if (start > end)
                throw new ArgumentException("Start Time must be before End Time");

            int pageSize = data.Data[INPUT_PAGE_SIZE] as int? ?? DEFAULT_PAGE_SIZE;
            if (pageSize < 1 || pageSize > MAX_PAGE_SIZE)
                throw new ArgumentException($"Page Size must be between 1 and {MAX_PAGE_SIZE}");

            string filterPattern = data.Data[INPUT_FILTER] as string;
            string streamPrefix = data.Data[INPUT_STREAM_PREFIX] as string;
            string nextToken = data.Data[INPUT_PAGE_TOKEN] as string;
            if (string.IsNullOrWhiteSpace(nextToken))
                nextToken = null;

            AWSCredentials credentials = connection.GetCredentials();
            var events = new List<CloudWatchLogEvent>();
            DateTime deadline = DateTime.UtcNow + PAGE_TIME_BUDGET;

            for (int call = 0; call < MAX_CALLS_PER_PAGE; call++)
            {
                if (call > 0)
                    Thread.Sleep(DELAY_BETWEEN_CALLS); // FilterLogEvents is limited to a few calls per second per account

                var request = new Dictionary<string, object>
                {
                    ["logGroupName"] = logGroupName,
                    ["startTime"] = new DateTimeOffset(start).ToUnixTimeMilliseconds(),
                    ["endTime"] = new DateTimeOffset(end).ToUnixTimeMilliseconds(),
                    ["limit"] = pageSize - events.Count
                };
                if (!string.IsNullOrWhiteSpace(filterPattern))
                    request["filterPattern"] = filterPattern;
                if (!string.IsNullOrWhiteSpace(streamPrefix))
                    request["logStreamNamePrefix"] = streamPrefix.Trim();
                if (nextToken != null)
                    request["nextToken"] = nextToken;

                string response = CloudWatchLogsApi.CallAsync(connection, credentials, "FilterLogEvents", request).GetAwaiter().GetResult();
                nextToken = ParseResponse(response, logGroupName, events);

                if (nextToken == null || events.Count >= pageSize || DateTime.UtcNow >= deadline)
                    break;
            }

            return new Dictionary<string, object>
            {
                { OUTPUT_EVENTS, events.ToArray() },
                { OUTPUT_NEXT_TOKEN, nextToken },
                { OUTPUT_HAS_MORE, nextToken != null }
            };
        }

        private static string ParseResponse(string json, string logGroupName, List<CloudWatchLogEvent> events)
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            if (root.TryGetProperty("events", out JsonElement list))
            {
                foreach (JsonElement e in list.EnumerateArray())
                {
                    events.Add(new CloudWatchLogEvent
                    {
                        Timestamp = e.TryGetProperty("timestamp", out JsonElement ts)
                            ? DateTimeOffset.FromUnixTimeMilliseconds(ts.GetInt64()).UtcDateTime
                            : default,
                        Message = e.TryGetProperty("message", out JsonElement m) ? m.GetString() : null,
                        LogStreamName = e.TryGetProperty("logStreamName", out JsonElement s) ? s.GetString() : null,
                        LogGroupName = logGroupName
                    });
                }
            }

            return root.TryGetProperty("nextToken", out JsonElement token) && token.ValueKind == JsonValueKind.String
                ? token.GetString()
                : null;
        }

        private static DateTime? AsUtc(DateTime? value)
        {
            if (value == null || value.Value == DateTime.MinValue)
                return null;
            return value.Value.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(value.Value, DateTimeKind.Local).ToUniversalTime()
                : value.Value.ToUniversalTime();
        }
    }
}

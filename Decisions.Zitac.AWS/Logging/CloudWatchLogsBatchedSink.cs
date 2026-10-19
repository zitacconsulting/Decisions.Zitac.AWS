using System.Text;
using System.Text.Json;
using Amazon.Runtime;
using Decisions.Zitac.AWS.Authentication;
using Serilog.Debugging;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Sinks.PeriodicBatching;

namespace Decisions.Zitac.AWS.Logging
{
    /// <summary>
    /// Sends batches to CloudWatch Logs through its JSON HTTP API, signed with AwsSigV4.
    ///
    /// Why not AWSSDK.CloudWatchLogs + Serilog.Sinks.AwsCloudWatch: Decisions (9.26 through 10.3) ships
    /// AWSSDK.CloudWatchLogs 3.7 in the Decisions.AWS module next to AWSSDK.Core 4.x in bin/, and that
    /// pair cannot load together (TypeLoadException: CreateDefaultClientConfig not implemented).
    /// Bundling CloudWatchLogs 4.x would clash with Decisions.AWS's copy of the same file name.
    ///
    /// The connection is resolved for every batch, not when the sink is configured: sinks are set up
    /// very early in boot, before module settings can be read (9.x reads them from the DB), and the
    /// system Zitac AWS settings can change later without the sink being reconfigured.
    /// Batching, queue limits and retry backoff come from Serilog.Sinks.PeriodicBatching (core bin/).
    /// </summary>
    public class CloudWatchLogsBatchedSink : IBatchedLogEventSink
    {
        // https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
        private const int MAX_EVENTS_PER_PUT = 10000;
        private const int MAX_BYTES_PER_PUT = 1_048_576;
        private const int EVENT_OVERHEAD_BYTES = 26;
        private const int MAX_EVENT_BYTES = 262_144 - EVENT_OVERHEAD_BYTES;


        /// <summary>
        /// One stream per server per process start, shared by every sink instance and log group, so
        /// saving the logging settings (which rebuilds the sink) doesn't start a new stream. The host
        /// name tells cluster nodes apart; the random suffix keeps nodes with identical host names
        /// (e.g. copied compose files) apart too. ':' and '*' are not allowed in stream names.
        /// </summary>
        public static readonly string LogStreamName =
            $"{Environment.MachineName}_{DateTime.UtcNow:yyyy-MM-dd-HH-mm-ss}_{Guid.NewGuid().ToString("N").Substring(0, 8)}";

        private readonly Func<AwsConnection> getConnection;
        private readonly LogGroupResolver groupResolver;
        private readonly ITextFormatter formatter;

        // PeriodicBatchingSink never calls EmitBatchAsync concurrently, so no locking is needed.
        private AWSCredentials credentials;
        private string connectionFingerprint;
        private readonly HashSet<string> readyGroups = new HashSet<string>(StringComparer.Ordinal);

        public CloudWatchLogsBatchedSink(Func<AwsConnection> getConnection, LogGroupResolver groupResolver, ITextFormatter formatter)
        {
            this.getConnection = getConnection;
            this.groupResolver = groupResolver;
            this.formatter = formatter;
        }

        public async Task EmitBatchAsync(IEnumerable<LogEvent> batch)
        {
            AwsConnection connection = getConnection();
            connection.Validate();

            string fingerprint = AwsCredentialFactory.GetFingerprint(connection);
            if (fingerprint != connectionFingerprint)
            {
                // Different account/region/identity: groups and streams must be checked again.
                credentials = connection.GetCredentials();
                connectionFingerprint = fingerprint;
                readyGroups.Clear();
            }

            var byGroup = batch
                .GroupBy(groupResolver.Resolve)
                .Select(g => (Group: g.Key, Events: g.OrderBy(e => e.Timestamp).Select(Render).ToList()))
                .ToList();

            // If every group fails (bad credentials, network) the exception makes PeriodicBatchingSink retry
            // the whole batch with backoff. If only some fail, retrying would duplicate the groups that
            // succeeded, so those failures are reported to SelfLog and their events dropped instead.
            var failures = new List<Exception>();
            foreach (var (group, events) in byGroup)
            {
                try
                {
                    await SendToGroupAsync(connection, group, events).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    failures.Add(ex);
                }
            }

            if (failures.Count == byGroup.Count && failures.Count > 0)
                throw failures.Count == 1 ? failures[0] : new AggregateException(failures);
            foreach (var failure in failures)
                SelfLog.WriteLine("Zitac AWS CloudWatch: dropped events for one log group: {0}", failure.Message);
        }

        private async Task SendToGroupAsync(AwsConnection connection, string logGroupName, List<(long Timestamp, string Message)> events)
        {
            if (!readyGroups.Contains(logGroupName))
            {
                await EnsureGroupAndStreamAsync(connection, logGroupName).ConfigureAwait(false);
                readyGroups.Add(logGroupName);
            }

            foreach (var chunk in SplitIntoPuts(events))
            {
                try
                {
                    await PutLogEventsAsync(connection, logGroupName, chunk).ConfigureAwait(false);
                }
                catch (CloudWatchLogsException ex) when (ex.ErrorType == "ResourceNotFoundException")
                {
                    // Group or stream deleted while running: recreate and retry once.
                    await EnsureGroupAndStreamAsync(connection, logGroupName).ConfigureAwait(false);
                    await PutLogEventsAsync(connection, logGroupName, chunk).ConfigureAwait(false);
                }
            }
        }

        public Task OnEmptyBatchAsync()
        {
            return Task.CompletedTask;
        }

        private async Task EnsureGroupAndStreamAsync(AwsConnection connection, string logGroupName)
        {
            string logStreamName = LogStreamName;
            try
            {
                await CallAsync(connection, "CreateLogGroup", new { logGroupName }).ConfigureAwait(false);
            }
            catch (CloudWatchLogsException ex) when (ex.ErrorType == "ResourceAlreadyExistsException" || ex.ErrorType == "AccessDeniedException")
            {
                // Already there, or the identity may only write to an existing group (PutLogEvents will tell).
            }

            try
            {
                await CallAsync(connection, "CreateLogStream", new { logGroupName, logStreamName }).ConfigureAwait(false);
            }
            catch (CloudWatchLogsException ex) when (ex.ErrorType == "ResourceAlreadyExistsException")
            {
            }
        }

        private Task PutLogEventsAsync(AwsConnection connection, string logGroupName, List<(long Timestamp, string Message)> events)
        {
            return CallAsync(connection, "PutLogEvents", new
            {
                logGroupName,
                logStreamName = LogStreamName,
                logEvents = events.Select(e => new { timestamp = e.Timestamp, message = e.Message })
            });
        }

        private Task CallAsync(AwsConnection connection, string action, object payload)
        {
            return CloudWatchLogsApi.CallAsync(connection, credentials, action, payload);
        }

        private (long Timestamp, string Message) Render(LogEvent logEvent)
        {
            using var writer = new StringWriter();
            formatter.Format(logEvent, writer);
            string message = writer.ToString().TrimEnd();
            if (message.Length == 0)
                message = " ";

            int bytes = Encoding.UTF8.GetByteCount(message);
            while (bytes > MAX_EVENT_BYTES)
            {
                message = message.Substring(0, (int)((long)message.Length * MAX_EVENT_BYTES / bytes) - 1);
                bytes = Encoding.UTF8.GetByteCount(message);
            }
            return (logEvent.Timestamp.ToUnixTimeMilliseconds(), message);
        }

        private static IEnumerable<List<(long Timestamp, string Message)>> SplitIntoPuts(List<(long Timestamp, string Message)> events)
        {
            var current = new List<(long, string)>();
            int currentBytes = 0;
            foreach (var e in events)
            {
                int size = Encoding.UTF8.GetByteCount(e.Message) + EVENT_OVERHEAD_BYTES;
                if (current.Count > 0 && (current.Count == MAX_EVENTS_PER_PUT || currentBytes + size > MAX_BYTES_PER_PUT))
                {
                    yield return current;
                    current = new List<(long, string)>();
                    currentBytes = 0;
                }
                current.Add(e);
                currentBytes += size;
            }
            if (current.Count > 0)
                yield return current;
        }
    }

    public class CloudWatchLogsException : Exception
    {
        public string ErrorType { get; }
        public int StatusCode { get; }

        public CloudWatchLogsException(string errorType, int statusCode, string message)
            : base(message)
        {
            ErrorType = errorType;
            StatusCode = statusCode;
        }

        internal static CloudWatchLogsException FromResponse(string action, int statusCode, string content)
        {
            string errorType = null;
            string message = content;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(content);
                if (doc.RootElement.TryGetProperty("__type", out JsonElement type))
                    errorType = type.GetString()?.Split('#').Last();
                if (doc.RootElement.TryGetProperty("message", out JsonElement m) || doc.RootElement.TryGetProperty("Message", out m))
                    message = m.GetString();
            }
            catch (JsonException)
            {
            }
            return new CloudWatchLogsException(errorType, statusCode, $"CloudWatch Logs {action} failed (HTTP {statusCode} {errorType}): {message}");
        }
    }
}

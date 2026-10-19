using System.Text.Json;
using Amazon.Runtime;
using Decisions.Zitac.AWS.Logging;

namespace Decisions.Zitac.AWS.Authentication
{
    /// <summary>
    /// Signed calls to the CloudWatch Logs JSON API (POST https://logs.[region].amazonaws.com/ with an
    /// X-Amz-Target header). Used instead of AWSSDK.CloudWatchLogs: the 3.7 copy Decisions.AWS ships can't
    /// load against the AWSSDK.Core 4.x Decisions ships (see CloudWatchLogsBatchedSink).
    /// </summary>
    public static class CloudWatchLogsApi
    {
        private const string JSON_CONTENT_TYPE = "application/x-amz-json-1.1";

        private static readonly HttpClient httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        /// <summary>Calls an action, e.g. "PutLogEvents", and returns the response body.</summary>
        public static async Task<string> CallAsync(AwsConnection connection, AWSCredentials credentials, string action, object payload)
        {
            string body = JsonSerializer.Serialize(payload);
            ImmutableCredentials immutable = await credentials.GetCredentialsAsync().ConfigureAwait(false);

            using HttpRequestMessage request = AwsSigV4.CreateSignedRequest("POST", connection.GetServiceEndpoint("logs"), "/",
                connection.Region, "logs", immutable, body, JSON_CONTENT_TYPE,
                new Dictionary<string, string> { { "X-Amz-Target", "Logs_20140328." + action } });
            using HttpResponseMessage response = await httpClient.SendAsync(request).ConfigureAwait(false);
            string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                throw CloudWatchLogsException.FromResponse(action, (int)response.StatusCode, content);
            return content;
        }
    }
}

using Amazon.Runtime;
using Decisions.Zitac.AWS.Authentication;
using DecisionsFramework;
using DecisionsFramework.Data.DataTypes;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.Mapping.InputImpl;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.Properties.Attributes;

namespace Decisions.Zitac.AWS.Steps
{
    public enum HttpMethod
    {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH
    }

    [AutoRegisterStep("Execute AWS Rest Method", "Integration", "AWS", "Zitac")]
    [Writable]
    public class ExecuteRestMethod : BaseAwsStep, IDefaultInputMappingStep
    {
        private const string REQUEST_CATEGORY = "Request";
        private const string INPUT_SERVICE = "AWS Service Name";
        private const string INPUT_PATH = "API Endpoint Path";
        private const string INPUT_METHOD = "HTTP Method";
        private const string INPUT_BODY = "Request Body";
        private const string INPUT_HEADERS = "Headers";
        private const string DEFAULT_CONTENT_TYPE = "application/json";
        private const int DEFAULT_TIMEOUT_SECONDS = 100;

        // Timeout is enforced per request with a CancellationToken so one shared client can serve all steps.
        private static readonly HttpClient httpClient = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

        [WritableValue]
        private string endpointUrl;

        [WritableValue]
        private string contentType = DEFAULT_CONTENT_TYPE;

        [WritableValue]
        private int timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;

        [PropertyClassification(new[] { INPUTS_CATEGORY }, "Request Info", 0)]
        [InfoOrWarningEditor(false, "https://docs.aws.amazon.com/general/latest/gr/aws-service-information.html", true)]
        public string InputsNote
        {
            get { return "Service: e.g. sts or dynamodb. Path: e.g. /?Action=GetCallerIdentity&Version=2011-06-15. Body and Headers are optional."; }
            set { }
        }

        [PropertyClassification(9, "Endpoint Info", REQUEST_CATEGORY)]
        [InfoOrWarningEditor(false, null, true)]
        public string EndpointNote
        {
            get { return "Endpoint URL Override is optional: empty calls https://[service].[region].amazonaws.com."; }
            set { }
        }

        [PropertyClassification(10, "Endpoint URL Override (optional)", REQUEST_CATEGORY)]
        public string EndpointUrl
        {
            get { return endpointUrl; }
            set { endpointUrl = value; OnPropertyChanged(nameof(EndpointUrl)); }
        }

        [PropertyClassification(11, "Content Type", REQUEST_CATEGORY)]
        public string ContentType
        {
            get { return contentType; }
            set { contentType = value; OnPropertyChanged(nameof(ContentType)); }
        }

        [PropertyClassification(12, "Timeout (seconds)", REQUEST_CATEGORY)]
        public int TimeoutSeconds
        {
            get { return timeoutSeconds; }
            set { timeoutSeconds = value; OnPropertyChanged(nameof(TimeoutSeconds)); }
        }

        protected override IEnumerable<DataDescription> StepInputs => new[]
        {
            new DataDescription(typeof(string), INPUT_SERVICE),
            new DataDescription(typeof(string), INPUT_PATH),
            new DataDescription(typeof(HttpMethod), INPUT_METHOD),
            new DataDescription(typeof(string), INPUT_BODY),
            new DataDescription(typeof(SimpleKeyValuePair), INPUT_HEADERS, true)
        };

        // Optional inputs start as Ignore so a plain GET only needs service, path and method.
        public IInputMapping[] DefaultInputs => new IInputMapping[]
        {
            new ConstantInputMapping { InputDataName = INPUT_METHOD, Value = HttpMethod.GET },
            new IgnoreInputMapping { InputDataName = INPUT_BODY },
            new IgnoreInputMapping { InputDataName = INPUT_HEADERS }
        };

        protected override DataDescription[] DoneOutputs => new[]
        {
            new DataDescription(typeof(string), "Response Content"),
            new DataDescription(typeof(int), "Status Code")
        };

        protected override Dictionary<string, object> RunStep(StepStartData data, AwsConnection connection)
        {
            string service = (data.Data[INPUT_SERVICE] as string)?.Trim();
            string path = data.Data[INPUT_PATH] as string;
            HttpMethod httpMethod = (HttpMethod)data.Data[INPUT_METHOD];
            string body = data.Data[INPUT_BODY] as string;
            var headers = (data.Data[INPUT_HEADERS] as IEnumerable<SimpleKeyValuePair>)?
                .Where(h => h != null && !string.IsNullOrWhiteSpace(h.Key))
                .Select(h => new KeyValuePair<string, string>(h.Key, h.Value))
                .ToList();

            if (string.IsNullOrEmpty(service))
                throw new ArgumentException("AWS Service Name is required");

            Uri endpoint = string.IsNullOrWhiteSpace(EndpointUrl)
                ? connection.GetServiceEndpoint(service)
                : new Uri(EndpointUrl.Trim());

            ImmutableCredentials credentials = connection.GetCredentials().GetCredentialsAsync().GetAwaiter().GetResult()
                ?? throw new Exception("Failed to obtain AWS credentials");

            using HttpRequestMessage request = AwsSigV4.CreateSignedRequest(httpMethod.ToString(), endpoint, path,
                connection.Region, service, credentials, body, ContentType,
                headers);
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(TimeoutSeconds));
            using HttpResponseMessage response = httpClient.SendAsync(request, cancellation.Token).GetAwaiter().GetResult();
            string responseContent = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            if (!response.IsSuccessStatusCode)
                throw new Exception($"AWS request failed with HTTP {(int)response.StatusCode} {response.StatusCode}: {responseContent}");

            return new Dictionary<string, object>
            {
                { "Response Content", responseContent },
                { "Status Code", (int)response.StatusCode }
            };
        }

        public override ValidationIssue[] GetValidationIssues()
        {
            var issues = new List<ValidationIssue>(base.GetValidationIssues());
            if (!string.IsNullOrWhiteSpace(EndpointUrl) && !Uri.TryCreate(EndpointUrl.Trim(), UriKind.Absolute, out _))
                issues.Add(new ValidationIssue(this, "Endpoint URL Override must be an absolute URL, e.g. https://iam.amazonaws.com", "", BreakLevel.Fatal, nameof(EndpointUrl)));
            if (TimeoutSeconds <= 0)
                issues.Add(new ValidationIssue(this, "Timeout must be greater than 0", "", BreakLevel.Fatal, nameof(TimeoutSeconds)));
            return issues.ToArray();
        }
    }
}

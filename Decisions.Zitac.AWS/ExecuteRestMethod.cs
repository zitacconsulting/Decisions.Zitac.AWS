using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using Amazon.Runtime;
using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.CoreSteps;

namespace Decisions.Zitac.AWS.Steps
{
    public enum AuthenticationMethod
    {
        AccessKeys,
        AWSDefaultCredentials
    }
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
    public class ExecuteRestMethod : BaseFlowAwareStep, ISyncStep, IDataConsumer, IDataProducer, INotifyPropertyChanged
    {
        [WritableValue]
        private AuthenticationMethod authenticationMethod;

        [PropertyClassification(1, "Authentication Method", new string[] { "AWS Settings" })]
        public AuthenticationMethod AuthenticationMethod
        {
            get { return authenticationMethod; }
            set
            {
                authenticationMethod = value;
                this.OnPropertyChanged(nameof(AuthenticationMethod));
                this.OnPropertyChanged("InputData");
            }
        }


        [WritableValue]
        private string region;

        [PropertyClassification(2, "AWS Region", "AWS Settings")]
        [SelectStringEditor("RegionOptions")]
        public string Region
        {
            get { return region; }
            set
            {
                region = value;
                OnPropertyChanged();
            }
        }

        [PropertyHidden]
        public string[] RegionOptions
        {
            get
            {
                return new string[]
                {
                    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                    "eu-west-1", "eu-west-2", "eu-central-1",
                    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
                    "sa-east-1"
                };
            }
        }

        public DataDescription[] InputData
        {
            get
            {
                var inputs = new List<DataDescription>();

                if (AuthenticationMethod == AuthenticationMethod.AccessKeys)
                {
                    inputs.Add(new DataDescription(typeof(string), "Access Key ID"){ Categories = new string[] { "Credentials" } });
                    inputs.Add(new DataDescription(typeof(string), "Secret Access Key"){ Categories = new string[] { "Credentials" } });
                }

                inputs.Add(new DataDescription(typeof(string), "AWS Service Name"));
                inputs.Add(new DataDescription(typeof(string), "API Endpoint Path"));
                inputs.Add(new DataDescription(typeof(HttpMethod), "HTTP Method"));
                inputs.Add(new DataDescription(typeof(string), "Request Body (JSON)"));

                return inputs.ToArray();
            }
        }

        public override OutcomeScenarioData[] OutcomeScenarios
        {
            get
            {
                return new OutcomeScenarioData[]
                {
                    new OutcomeScenarioData("Done", new DataDescription(typeof(string), "Response Content")),
                    new OutcomeScenarioData("Error", new DataDescription(typeof(string), "Error Message"))
                };
            }
        }

        public ResultData Run(StepStartData data)
        {
            try
            {
                string accessKey, secretKey, service, requestUri, requestPayload;
                HttpMethod httpMethod;
                AWSCredentials credentials;

                if (AuthenticationMethod == AuthenticationMethod.AccessKeys)
                {
                    accessKey = data.Data["Access Key ID"] as string;
                    secretKey = data.Data["Secret Access Key"] as string;
                    credentials = new BasicAWSCredentials(accessKey, secretKey);
                }
                else
                {
                    credentials = FallbackCredentialsFactory.GetCredentials();
                }


                service = data.Data["AWS Service Name"] as string;
                requestUri = data.Data["API Endpoint Path"] as string;
                httpMethod = (HttpMethod)data.Data["HTTP Method"];
                requestPayload = data.Data["Request Body (JSON)"] as string;

                var response = ExecuteAWSRequest(credentials, region, service, requestUri, httpMethod, requestPayload).Result;
                

                return new ResultData("Done", new Dictionary<string, object>
                {
                    { "Response Content", response }
                });
            }
            catch (Exception ex)
            {
                return new ResultData("Error", new Dictionary<string, object>
                {
                    { "Error Message", ex.Message }
                });
            }
        }



private async Task<string> ExecuteAWSRequest(AWSCredentials credentials, string region, string service, string requestUri, HttpMethod httpMethod, string requestPayload)
{

        var endpoint = new Uri($"https://{service}.{region.ToLower()}.amazonaws.com");
        var request = new HttpRequestMessage(new System.Net.Http.HttpMethod(httpMethod.ToString()), new Uri(endpoint, requestUri));

        // Get AWS credentials - this will fetch from the container's metadata endpoint when using IAM Role
        var awsCredentials = await credentials.GetCredentialsAsync();
        if (awsCredentials == null)
        {
            throw new Exception("Failed to obtain AWS credentials");
        }

        // Create a date for headers and the credential string
        var dateTime = DateTime.UtcNow;
        var dateStamp = dateTime.ToString("yyyyMMdd");
        var amzDateTime = dateTime.ToString("yyyyMMddTHHmmssZ");

        // Calculate payload hash
        var payloadHash = CalculateHash(requestPayload ?? string.Empty);

        // Set the request payload
        if (!string.IsNullOrEmpty(requestPayload))
        {
            request.Content = new StringContent(requestPayload, Encoding.UTF8, "application/json");
        }

        // Initialize headers dictionary to maintain order
        var headers = new SortedDictionary<string, string>
        {
            { "host", endpoint.Host },
            { "x-amz-content-sha256", payloadHash },
            { "x-amz-date", amzDateTime }
        };

        // Add security token for temporary credentials (IAM Role)
        if (!string.IsNullOrEmpty(awsCredentials.Token))
        {
            headers.Add("x-amz-security-token", awsCredentials.Token);
        }

        // Add all headers to request
        foreach (var header in headers)
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        // Add content-type if present
        if (request.Content != null)
        {
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            headers.Add("content-type", "application/json");
        }

        var credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";

        // Create canonical headers string
        var canonicalHeaders = new StringBuilder();
        foreach (var header in headers)
        {
            canonicalHeaders.AppendLine($"{header.Key}:{header.Value}");
        }

        // Create signed headers string
        var signedHeaders = string.Join(";", headers.Keys);

        // Create canonical request
        var canonicalRequest = new StringBuilder();
        canonicalRequest.AppendLine(request.Method.ToString());
        canonicalRequest.AppendLine(request.RequestUri.AbsolutePath);
        canonicalRequest.AppendLine(string.Empty); // Empty query string
        canonicalRequest.Append(canonicalHeaders);
        canonicalRequest.AppendLine();
        canonicalRequest.AppendLine(signedHeaders);
        canonicalRequest.Append(payloadHash);

        var canonicalRequestString = canonicalRequest.ToString();
        var canonicalRequestHash = CalculateHash(canonicalRequestString);

        // Create string to sign
        var stringToSign = $"AWS4-HMAC-SHA256\n{amzDateTime}\n{credentialScope}\n{canonicalRequestHash}";

        // Calculate signature
        var kSecret = Encoding.UTF8.GetBytes($"AWS4{awsCredentials.SecretKey}");
        var kDate = HmacSha256(kSecret, dateStamp);
        var kRegion = HmacSha256(kDate, region);
        var kService = HmacSha256(kRegion, service);
        var kSigning = HmacSha256(kService, "aws4_request");
        var signature = BitConverter.ToString(HmacSha256(kSigning, stringToSign)).Replace("-", "").ToLowerInvariant();

        // Add authorization header
        var authorizationHeader = $"AWS4-HMAC-SHA256 Credential={awsCredentials.AccessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";
        request.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);

        // Execute the request
        using (var client = new HttpClient())
        {
            var response = await client.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();
            
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"AWS request failed with status code {response.StatusCode}: {responseContent}");
            }
            
            return responseContent;
        }
    

}

        private byte[] HmacSha256(byte[] key, string data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            }
        }

        private string CalculateHash(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            }
        }

    }
}


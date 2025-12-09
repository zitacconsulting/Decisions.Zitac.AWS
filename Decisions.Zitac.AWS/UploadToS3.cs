using System.ComponentModel;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.CoreSteps;

namespace Decisions.Zitac.AWS.Steps
{
    [AutoRegisterStep("Upload File to S3", "Integration", "AWS", "Zitac")]
    [Writable]
    public class UploadFileToS3 : BaseFlowAwareStep, ISyncStep, IDataConsumer, IDataProducer, INotifyPropertyChanged
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
                    inputs.Add(new DataDescription(typeof(string), "Access Key ID") { Categories = new string[] { "Credentials" } });
                    inputs.Add(new DataDescription(typeof(string), "Secret Access Key") { Categories = new string[] { "Credentials" } });
                }

                inputs.Add(new DataDescription(typeof(string), "S3 URI"));
                inputs.Add(new DataDescription(typeof(string), "File Name"));
                inputs.Add(new DataDescription(typeof(byte), "File Content", isList: true));
                inputs.Add(new DataDescription(typeof(string), "Content Type"));

                return inputs.ToArray();
            }
        }

        public override OutcomeScenarioData[] OutcomeScenarios
        {
            get
            {
                return new OutcomeScenarioData[]
                {
                    new OutcomeScenarioData("Done", new DataDescription(typeof(string), "Full S3 URI")),
                    new OutcomeScenarioData("Error", new DataDescription(typeof(string), "Error Message"))
                };
            }
        }

        public ResultData Run(StepStartData data)
        {
            try
            {
                string accessKey, secretKey, s3Uri, fileName, contentType;
                byte[] fileContent;
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

                s3Uri = data.Data["S3 URI"] as string;
                fileName = data.Data["File Name"] as string;
                fileContent = data.Data["File Content"] as byte[];
                contentType = data.Data["Content Type"] as string ?? "application/octet-stream";

                if (string.IsNullOrEmpty(s3Uri))
                    throw new ArgumentException("S3 URI is required");

                if (string.IsNullOrEmpty(fileName))
                    throw new ArgumentException("File Name is required");

                if (fileContent == null || fileContent.Length == 0)
                    throw new ArgumentException("File Content is required");

                // Parse S3 URI
                var parsedUri = ParseS3Uri(s3Uri);
                var bucketName = parsedUri.Item1;
                var basePath = parsedUri.Item2;

                // Combine base path with filename
                var fullPath = string.IsNullOrEmpty(basePath)
                    ? fileName
                    : $"{basePath.TrimEnd('/')}/{fileName}";

                var fullS3Uri = UploadToS3(credentials, region, bucketName, fullPath, fileContent, contentType);

                return new ResultData("Done", new Dictionary<string, object>
                {
                    { "Full S3 URI", fullS3Uri }
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

        private Tuple<string, string> ParseS3Uri(string s3Uri)
        {
            // Remove s3:// prefix
            if (!s3Uri.StartsWith("s3://", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("S3 URI must start with s3://");
            }

            var withoutPrefix = s3Uri.Substring(5);
            var parts = withoutPrefix.Split(new[] { '/' }, 2);

            var bucketName = parts[0];
            var path = parts.Length > 1 ? parts[1] : string.Empty;

            return new Tuple<string, string>(bucketName, path);
        }

        private string UploadToS3(AWSCredentials credentials, string region, string bucketName, string fileKey, byte[] fileContent, string contentType)
        {
            // Get credentials asynchronously like in your ExecuteRestMethod
            var awsCredentials = credentials.GetCredentialsAsync().Result;

            AmazonS3Client s3Client;

            // Check if we have a session token (temporary credentials)
            if (!string.IsNullOrEmpty(awsCredentials.Token))
            {
                var config = new AmazonS3Config
                {
                    RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(region)
                };
                s3Client = new AmazonS3Client(awsCredentials.AccessKey, awsCredentials.SecretKey, awsCredentials.Token, config);
            }
            else
            {
                s3Client = new AmazonS3Client(awsCredentials.AccessKey, awsCredentials.SecretKey, region);
            }

            using (s3Client)
            {
                using (var memoryStream = new MemoryStream(fileContent))
                {
                    var putRequest = new PutObjectRequest
                    {
                        BucketName = bucketName,
                        Key = fileKey,
                        InputStream = memoryStream,
                        ContentType = contentType
                    };

                    var response = s3Client.PutObjectAsync(putRequest).Result;

                    if (response.HttpStatusCode != System.Net.HttpStatusCode.OK)
                    {
                        throw new Exception($"S3 upload failed with status code: {response.HttpStatusCode}");
                    }

                    return $"s3://{bucketName}/{fileKey}";
                }
            }
        }
    }
}
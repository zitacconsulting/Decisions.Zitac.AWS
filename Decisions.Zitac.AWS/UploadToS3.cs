using Amazon.S3;
using Amazon.S3.Model;
using Decisions.Zitac.AWS.Authentication;
using Microsoft.AspNetCore.StaticFiles;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.Mapping.InputImpl;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.Properties.Attributes;

namespace Decisions.Zitac.AWS.Steps
{
    [AutoRegisterStep("Upload File to S3", "Integration", "AWS", "Zitac")]
    [Writable]
    public class UploadFileToS3 : BaseAwsStep, IDefaultInputMappingStep
    {
        private const string DEFAULT_CONTENT_TYPE = "application/octet-stream";

        // ASP.NET Core's extension → MIME type table (~380 types); read-only use is thread-safe.
        private static readonly FileExtensionContentTypeProvider contentTypeProvider = CreateContentTypeProvider();

        private static FileExtensionContentTypeProvider CreateContentTypeProvider()
        {
            var provider = new FileExtensionContentTypeProvider();
            // The table's .zip entry is the legacy Windows "application/x-zip-compressed"; use the IANA type.
            provider.Mappings[".zip"] = "application/zip";
            return provider;
        }

        [PropertyClassification(new[] { INPUTS_CATEGORY }, "Upload Info", 0)]
        [InfoOrWarningEditor(false, "https://developer.mozilla.org/en-US/docs/Web/HTTP/MIME_types/Common_types", true)]
        public string InputsNote
        {
            get { return "S3 URI: s3://bucket/ or s3://bucket/folder/. File Name is added to it. Content Type is detected from the file name if ignored."; }
            set { }
        }

        public IInputMapping[] DefaultInputs => new IInputMapping[]
        {
            new IgnoreInputMapping { InputDataName = "Content Type" }
        };

        protected override IEnumerable<DataDescription> StepInputs => new[]
        {
            new DataDescription(typeof(string), "S3 URI"),
            new DataDescription(typeof(string), "File Name"),
            new DataDescription(typeof(byte), "File Content", true),
            new DataDescription(typeof(string), "Content Type")
        };

        protected override DataDescription[] DoneOutputs => new[]
        {
            new DataDescription(typeof(string), "Full S3 URI"),
            new DataDescription(typeof(string), "Content Type"),
            new DataDescription(typeof(string), "ETag"),
            new DataDescription(typeof(string), "Version Id")
        };

        protected override Dictionary<string, object> RunStep(StepStartData data, AwsConnection connection)
        {
            string s3Uri = data.Data["S3 URI"] as string;
            string fileName = data.Data["File Name"] as string;
            byte[] fileContent = data.Data["File Content"] as byte[];
            string contentType = data.Data["Content Type"] as string;

            if (string.IsNullOrWhiteSpace(s3Uri))
                throw new ArgumentException("S3 URI is required");
            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("File Name is required");
            if (fileContent == null || fileContent.Length == 0)
                throw new ArgumentException("File Content is required");

            // Like the AWS CLI: when no content type is given, derive it from the file extension, so browsers
            // open e.g. PDFs and images from S3 links instead of downloading them as unknown binary data.
            if (string.IsNullOrWhiteSpace(contentType))
                contentType = contentTypeProvider.TryGetContentType(fileName, out string detected) ? detected : DEFAULT_CONTENT_TYPE;

            ParseS3Uri(s3Uri.Trim(), out string bucketName, out string basePath);
            string key = string.IsNullOrEmpty(basePath)
                ? fileName.TrimStart('/')
                : $"{basePath}/{fileName.TrimStart('/')}";

            using var s3Client = new AmazonS3Client(connection.GetCredentials(), new AmazonS3Config
            {
                RegionEndpoint = connection.RegionEndpoint
            });
            using var stream = new MemoryStream(fileContent);

            PutObjectResponse response = s3Client.PutObjectAsync(new PutObjectRequest
            {
                BucketName = bucketName,
                Key = key,
                InputStream = stream,
                ContentType = contentType.Trim()
            }).GetAwaiter().GetResult();

            if (response.HttpStatusCode != System.Net.HttpStatusCode.OK)
                throw new Exception($"S3 upload failed with status code: {response.HttpStatusCode}");

            return new Dictionary<string, object>
            {
                { "Full S3 URI", $"s3://{bucketName}/{key}" },
                { "Content Type", contentType.Trim() },
                { "ETag", response.ETag },
                { "Version Id", response.VersionId }
            };
        }

        private static void ParseS3Uri(string s3Uri, out string bucketName, out string path)
        {
            if (!s3Uri.StartsWith("s3://", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("S3 URI must start with s3://");

            string[] parts = s3Uri.Substring(5).Split('/', 2);
            bucketName = parts[0];
            path = parts.Length > 1 ? parts[1].Trim('/') : string.Empty;

            if (string.IsNullOrEmpty(bucketName))
                throw new ArgumentException("S3 URI must contain a bucket name, e.g. s3://my-bucket/folder");
        }
    }
}

using Amazon;
using Amazon.Runtime;
using Decisions.Zitac.AWS.Steps;

namespace Decisions.Zitac.AWS.Authentication
{
    /// <summary>
    /// A fully resolved AWS connection (region + how to authenticate), regardless of whether it
    /// came from system settings, project settings, step configuration or the logging sink.
    /// </summary>
    public class AwsConnection
    {
        public const string DEFAULT_ROLE_SESSION_NAME = "Decisions-Zitac-AWS";
        public const int DEFAULT_SESSION_DURATION_MINUTES = 60;

        public string Region { get; set; }
        public AuthenticationMethod AuthenticationMethod { get; set; }
        public string AccessKeyId { get; set; }
        public string SecretAccessKey { get; set; }
        public bool AssumeRole { get; set; }
        public string RoleArn { get; set; }
        public string ExternalId { get; set; }
        public string RoleSessionName { get; set; }
        public int SessionDurationMinutes { get; set; } = DEFAULT_SESSION_DURATION_MINUTES;

        public RegionEndpoint RegionEndpoint => RegionEndpoint.GetBySystemName(Region);

        /// <summary>Default regional endpoint, e.g. https://logs.eu-north-1.amazonaws.com (amazonaws.com.cn in China).</summary>
        public Uri GetServiceEndpoint(string service)
        {
            string dnsSuffix = RegionEndpoint.PartitionDnsSuffix;
            if (string.IsNullOrEmpty(dnsSuffix))
                dnsSuffix = "amazonaws.com";
            return new Uri($"https://{service}.{Region.ToLowerInvariant()}.{dnsSuffix}");
        }

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(Region))
                throw new ArgumentException("AWS Region is not configured");

            if (AuthenticationMethod == AuthenticationMethod.AccessKeys
                && (string.IsNullOrWhiteSpace(AccessKeyId) || string.IsNullOrWhiteSpace(SecretAccessKey)))
                throw new ArgumentException("Access Key ID and Secret Access Key are required when using Access Keys");

            if (AssumeRole && string.IsNullOrWhiteSpace(RoleArn))
                throw new ArgumentException("Role ARN is required when Assume Role is enabled");

            // STS accepts 15 minutes up to the role's MaxSessionDuration (max 12 hours).
            if (AssumeRole && (SessionDurationMinutes < 15 || SessionDurationMinutes > 720))
                throw new ArgumentException("Session Duration must be between 15 and 720 minutes");
        }

        public AWSCredentials GetCredentials()
        {
            Validate();
            return AwsCredentialFactory.GetCredentials(this);
        }
    }
}

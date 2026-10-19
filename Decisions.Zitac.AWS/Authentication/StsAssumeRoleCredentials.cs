using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;

namespace Decisions.Zitac.AWS.Authentication
{
    /// <summary>
    /// Assume-role credentials that call STS in the connection's own region. The SDK's built-in
    /// AssumeRoleAWSCredentials picks the STS region from the environment and otherwise falls back
    /// to us-east-1, which fails for servers without internet access (VPC endpoint only) and
    /// ignores the region configured in Decisions.
    /// </summary>
    public class StsAssumeRoleCredentials : RefreshingAWSCredentials
    {
        private readonly AWSCredentials sourceCredentials;
        private readonly RegionEndpoint stsRegion;
        private readonly string roleArn;
        private readonly string roleSessionName;
        private readonly string externalId;
        private readonly int durationSeconds;

        public StsAssumeRoleCredentials(AWSCredentials sourceCredentials, RegionEndpoint stsRegion, string roleArn,
            string roleSessionName, string externalId, int durationSeconds)
        {
            this.sourceCredentials = sourceCredentials;
            this.stsRegion = stsRegion;
            this.roleArn = roleArn;
            this.roleSessionName = roleSessionName;
            this.externalId = externalId;
            this.durationSeconds = durationSeconds;

            // Refresh a little before expiry so a long-running call never gets expired credentials.
            PreemptExpiryTime = TimeSpan.FromMinutes(5);
        }

        protected override CredentialsRefreshState GenerateNewCredentials()
        {
            return GenerateNewCredentialsAsync().GetAwaiter().GetResult();
        }

        protected override async Task<CredentialsRefreshState> GenerateNewCredentialsAsync()
        {
            using var sts = new AmazonSecurityTokenServiceClient(sourceCredentials, new AmazonSecurityTokenServiceConfig
            {
                RegionEndpoint = stsRegion
            });

            AssumeRoleResponse response = await sts.AssumeRoleAsync(new AssumeRoleRequest
            {
                RoleArn = roleArn,
                RoleSessionName = roleSessionName,
                ExternalId = externalId,
                DurationSeconds = durationSeconds
            }).ConfigureAwait(false);

            Credentials credentials = response.Credentials;
            DateTime? expiration = credentials.Expiration;

            return new CredentialsRefreshState(
                new ImmutableCredentials(credentials.AccessKeyId, credentials.SecretAccessKey, credentials.SessionToken),
                expiration ?? DateTime.UtcNow.AddMinutes(15));
        }
    }
}

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Amazon.Runtime;
using Amazon.Runtime.Credentials;
using Decisions.Zitac.AWS.Steps;

namespace Decisions.Zitac.AWS.Authentication
{
    /// <summary>
    /// Builds AWSCredentials for an AwsConnection. Assume-role credentials are cached per distinct
    /// connection so STS is only called when the temporary credentials are about to expire,
    /// not on every step execution.
    /// </summary>
    public static class AwsCredentialFactory
    {
        private const int MAX_CACHED_CREDENTIALS = 200;

        private static readonly ConcurrentDictionary<string, AWSCredentials> assumeRoleCache = new ConcurrentDictionary<string, AWSCredentials>();

        public static AWSCredentials GetCredentials(AwsConnection connection)
        {
            AWSCredentials baseCredentials = GetBaseCredentials(connection);

            if (!connection.AssumeRole)
                return baseCredentials;

            string key = GetFingerprint(connection);
            if (assumeRoleCache.TryGetValue(key, out AWSCredentials cached))
                return cached;

            // Dynamic per-execution keys would otherwise grow the cache forever.
            if (assumeRoleCache.Count >= MAX_CACHED_CREDENTIALS)
                assumeRoleCache.Clear();

            return assumeRoleCache.GetOrAdd(key, _ => new StsAssumeRoleCredentials(
                baseCredentials,
                connection.RegionEndpoint,
                connection.RoleArn.Trim(),
                string.IsNullOrWhiteSpace(connection.RoleSessionName) ? AwsConnection.DEFAULT_ROLE_SESSION_NAME : connection.RoleSessionName.Trim(),
                string.IsNullOrWhiteSpace(connection.ExternalId) ? null : connection.ExternalId.Trim(),
                connection.SessionDurationMinutes * 60));
        }

        private static AWSCredentials GetBaseCredentials(AwsConnection connection)
        {
            if (connection.AuthenticationMethod == AuthenticationMethod.AccessKeys)
                return new BasicAWSCredentials(connection.AccessKeyId.Trim(), connection.SecretAccessKey.Trim());

            // SDK default chain: environment variables, shared credentials/config file,
            // ECS container credentials, EC2 instance profile, etc.
            return DefaultAWSCredentialsIdentityResolver.GetCredentials();
        }

        /// <summary>Identifies a connection's effective configuration without exposing its secret.</summary>
        public static string GetFingerprint(AwsConnection connection)
        {
            string raw = string.Join("\n",
                connection.AuthenticationMethod,
                connection.AccessKeyId,
                connection.SecretAccessKey,
                connection.Region,
                connection.RoleArn,
                connection.ExternalId,
                connection.RoleSessionName,
                connection.SessionDurationMinutes);
            // Hashed so secrets are never kept as dictionary keys.
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        }
    }
}

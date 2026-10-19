using System.Net;
using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;

namespace Decisions.Zitac.AWS.Authentication
{
    public static class AwsHelper
    {
        /// <summary>All regions known to the shipped AWS SDK, so new regions don't need a code change.</summary>
        public static string[] AllRegions => RegionEndpoint.EnumerableAllRegions
            .Select(r => r.SystemName)
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToArray();

        /// <summary>Unwraps async/aggregate wrappers and adds the AWS error code and request id when there is one.</summary>
        public static string DescribeException(Exception ex)
        {
            while ((ex is AggregateException || ex is System.Reflection.TargetInvocationException) && ex.InnerException != null)
                ex = ex.InnerException;

            if (ex is AmazonServiceException ase)
            {
                var details = new List<string>();
                if (!string.IsNullOrEmpty(ase.ErrorCode)) details.Add($"ErrorCode: {ase.ErrorCode}");
                if (ase.StatusCode != 0) details.Add($"HTTP {(int)ase.StatusCode} {ase.StatusCode}");
                if (!string.IsNullOrEmpty(ase.RequestId)) details.Add($"RequestId: {ase.RequestId}");
                return details.Count == 0 ? ase.Message : $"{ase.Message} ({string.Join(", ", details)})";
            }

            return ex.Message;
        }

        /// <summary>Calls STS GetCallerIdentity, which needs no IAM permissions, to verify a connection.</summary>
        public static string TestConnection(AwsConnection connection)
        {
            try
            {
                AWSCredentials credentials = connection.GetCredentials();
                using var sts = new AmazonSecurityTokenServiceClient(credentials, new AmazonSecurityTokenServiceConfig
                {
                    RegionEndpoint = connection.RegionEndpoint
                });
                GetCallerIdentityResponse identity = sts.GetCallerIdentityAsync(new GetCallerIdentityRequest()).GetAwaiter().GetResult();

                return "<p><b>Connection successful.</b></p>"
                    + $"<p>Region: {WebUtility.HtmlEncode(connection.Region)}<br/>"
                    + $"Account: {WebUtility.HtmlEncode(identity.Account)}<br/>"
                    + $"Identity ARN: {WebUtility.HtmlEncode(identity.Arn)}</p>";
            }
            catch (Exception ex)
            {
                return $"<p><b>Connection failed.</b></p><p>{WebUtility.HtmlEncode(DescribeException(ex))}</p>";
            }
        }
    }
}

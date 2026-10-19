using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Amazon.Runtime;

namespace Decisions.Zitac.AWS.Authentication
{
    /// <summary>
    /// AWS Signature Version 4 for raw HTTP requests.
    /// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
    /// The request is built from the same encoded path/query that is signed, so what goes on the
    /// wire always matches the canonical request.
    /// </summary>
    public static class AwsSigV4
    {
        public static HttpRequestMessage CreateSignedRequest(string httpMethod, Uri endpoint, string pathAndQuery,
            string region, string service, ImmutableCredentials credentials, string body, string contentType,
            IEnumerable<KeyValuePair<string, string>> extraHeaders = null)
        {
            SplitPathAndQuery(pathAndQuery ?? string.Empty, out string rawPath, out string rawQuery);

            // Endpoint may carry a base path itself (e.g. an API Gateway stage URL).
            string combinedPath = endpoint.AbsolutePath.TrimEnd('/') + "/" + rawPath.TrimStart('/');
            string[] segments = combinedPath.Split('/');
            string[] encodedSegments = segments.Select(s => Uri.EscapeDataString(Uri.UnescapeDataString(s))).ToArray();
            string wirePath = string.Join("/", encodedSegments);
            // S3 signs the path as sent; every other service signs it URI-encoded a second time.
            string canonicalPath = service == "s3"
                ? wirePath
                : string.Join("/", encodedSegments.Select(Uri.EscapeDataString));
            if (string.IsNullOrEmpty(wirePath)) wirePath = "/";
            if (string.IsNullOrEmpty(canonicalPath)) canonicalPath = "/";

            string query = BuildCanonicalQuery(rawQuery);

            var uri = new Uri(endpoint.GetLeftPart(UriPartial.Authority) + wirePath + (query.Length > 0 ? "?" + query : string.Empty));
            var request = new HttpRequestMessage(new System.Net.Http.HttpMethod(httpMethod), uri);

            DateTime now = DateTime.UtcNow;
            string dateStamp = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
            string amzDate = now.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
            string payloadHash = Sha256Hex(body ?? string.Empty);

            var headers = new SortedDictionary<string, string>(StringComparer.Ordinal)
            {
                { "host", uri.IsDefaultPort ? uri.Host : uri.Authority },
                { "x-amz-content-sha256", payloadHash },
                { "x-amz-date", amzDate }
            };
            if (!string.IsNullOrEmpty(credentials.Token))
                headers.Add("x-amz-security-token", credentials.Token);

            // Caller headers: names are case-insensitive (last one wins), values get SigV4's whitespace
            // normalization and are sent exactly as signed. A Content-Type header overrides contentType.
            var contentHeaders = new SortedDictionary<string, string>(StringComparer.Ordinal);
            if (extraHeaders != null)
            {
                foreach (var header in extraHeaders)
                {
                    string name = header.Key?.Trim().ToLowerInvariant();
                    if (string.IsNullOrEmpty(name))
                        continue;
                    if (ManagedHeaders.Contains(name))
                        throw new ArgumentException($"Header '{header.Key}' is set automatically when the request is signed and can't be supplied");

                    string value = NormalizeHeaderValue(header.Value);
                    if (name == "content-type")
                        contentType = value;
                    else if (name.StartsWith("content-", StringComparison.Ordinal) || name == "expires")
                        contentHeaders[name] = value;
                    else
                        headers[name] = value;
                }
            }

            if (!string.IsNullOrEmpty(body))
            {
                request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
                if (!string.IsNullOrWhiteSpace(contentType))
                    contentHeaders["content-type"] = NormalizeHeaderValue(contentType);
            }
            else if (contentHeaders.Count > 0)
            {
                throw new ArgumentException($"Header '{contentHeaders.Keys.First()}' describes the request body, but there is no body");
            }

            // .NET only sends Content-* headers when they're attached to the content, not the request.
            // Added without validation so the value sent is byte-for-byte the value signed.
            foreach (var header in contentHeaders)
            {
                request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                headers[header.Key] = header.Value;
            }

            foreach (var header in headers)
            {
                if (header.Key != "host" && !contentHeaders.ContainsKey(header.Key)
                    && !request.Headers.TryAddWithoutValidation(header.Key, header.Value))
                    throw new ArgumentException($"Header '{header.Key}' can't be sent with this request");
            }

            string canonicalHeaders = string.Concat(headers.Select(h => $"{h.Key}:{h.Value}\n"));
            string signedHeaders = string.Join(";", headers.Keys);
            string canonicalRequest = string.Join("\n", httpMethod, canonicalPath, query, canonicalHeaders, signedHeaders, payloadHash);

            string credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";
            string stringToSign = string.Join("\n", "AWS4-HMAC-SHA256", amzDate, credentialScope, Sha256Hex(canonicalRequest));

            byte[] kDate = HmacSha256(Encoding.UTF8.GetBytes("AWS4" + credentials.SecretKey), dateStamp);
            byte[] kRegion = HmacSha256(kDate, region);
            byte[] kService = HmacSha256(kRegion, service);
            byte[] kSigning = HmacSha256(kService, "aws4_request");
            string signature = Convert.ToHexString(HmacSha256(kSigning, stringToSign)).ToLowerInvariant();

            request.Headers.TryAddWithoutValidation("Authorization",
                $"AWS4-HMAC-SHA256 Credential={credentials.AccessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}");

            return request;
        }

        // Set by the signing process itself; a caller-supplied value would break or bypass the signature.
        private static readonly HashSet<string> ManagedHeaders = new HashSet<string>(StringComparer.Ordinal)
        {
            "host", "authorization", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"
        };

        /// <summary>SigV4 canonical form: trimmed, with runs of whitespace collapsed to one space.</summary>
        private static string NormalizeHeaderValue(string value)
        {
            return string.Join(" ", (value ?? string.Empty).Split((char[])null, StringSplitOptions.RemoveEmptyEntries));
        }

        private static void SplitPathAndQuery(string pathAndQuery, out string path, out string query)
        {
            int index = pathAndQuery.IndexOf('?');
            path = index < 0 ? pathAndQuery : pathAndQuery.Substring(0, index);
            query = index < 0 ? string.Empty : pathAndQuery.Substring(index + 1);
        }

        private static string BuildCanonicalQuery(string rawQuery)
        {
            return string.Join("&", rawQuery
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(pair =>
                {
                    int index = pair.IndexOf('=');
                    string name = index < 0 ? pair : pair.Substring(0, index);
                    string value = index < 0 ? string.Empty : pair.Substring(index + 1);
                    return (Name: Uri.EscapeDataString(Uri.UnescapeDataString(name)), Value: Uri.EscapeDataString(Uri.UnescapeDataString(value)));
                })
                .OrderBy(p => p.Name, StringComparer.Ordinal)
                .ThenBy(p => p.Value, StringComparer.Ordinal)
                .Select(p => p.Name + "=" + p.Value));
        }

        private static string Sha256Hex(string input)
        {
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
        }

        private static byte[] HmacSha256(byte[] key, string data)
        {
            return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(data));
        }
    }
}

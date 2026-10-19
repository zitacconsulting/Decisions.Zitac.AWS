using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using Decisions.Zitac.AWS.Authentication;
using DecisionsFramework;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.Flow.CoreSteps;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.Properties.Attributes;

namespace Decisions.Zitac.AWS.Steps
{
    [AutoRegisterStep("Generate SES SMTP Password", "Integration", "AWS", "Zitac")]
    [Writable]
    public class GenerateSesSmtpPassword : BaseFlowAwareStep, ISyncStep, IDataConsumer, IDataProducer, INotifyPropertyChanged, IValidationSource
    {
        [WritableValue]
        private string region;

        [PropertyClassification(1, "AWS Region", "AWS Settings")]
        [SelectStringEditor(nameof(RegionOptions))]
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
        public string[] RegionOptions => AwsHelper.AllRegions;

        [PropertyClassification(new[] { "Credentials" }, "SES SMTP Info", 0)]
        [InfoOrWarningEditor(false, "https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html", true)]
        public string InputsNote
        {
            get { return "Use the IAM user's Access Key ID as SMTP user and the result as password, on email-smtp.[region].amazonaws.com:587."; }
            set { }
        }

        public ValidationIssue[] GetValidationIssues()
        {
            return string.IsNullOrEmpty(region)
                ? new[] { new ValidationIssue(this, "Select the AWS Region of the SES endpoint you will send through", "", BreakLevel.Fatal, nameof(Region)) }
                : Array.Empty<ValidationIssue>();
        }

        public DataDescription[] InputData
        {
            get
            {
                return new DataDescription[]
                {
                    new DataDescription(typeof(string), "Secret Access Key") { Categories = new string[] { "Credentials" } }
                };
            }
        }

        public override OutcomeScenarioData[] OutcomeScenarios
        {
            get
            {
                return new OutcomeScenarioData[]
                {
                    new OutcomeScenarioData("Done", new DataDescription(typeof(string), "SMTP Password")),
                    new OutcomeScenarioData("Error", new DataDescription(typeof(string), "Error Message"))
                };
            }
        }

        public ResultData Run(StepStartData data)
        {
            try
            {
                var secretAccessKey = (data.Data["Secret Access Key"] as string)?.Trim();

                if (string.IsNullOrEmpty(secretAccessKey))
                    throw new ArgumentException("Secret Access Key is required");

                if (string.IsNullOrEmpty(region))
                    throw new ArgumentException("AWS Region must be selected");

                var smtpPassword = DeriveSmtpPassword(secretAccessKey, region);

                return new ResultData("Done", new Dictionary<string, object>
                {
                    { "SMTP Password", smtpPassword }
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

        private static string DeriveSmtpPassword(string secretAccessKey, string region)
        {
            // AWS SES SMTP password derivation algorithm
            // https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
            byte version = 0x04;
            string message = "SendRawEmail";

            var kDate = HmacSha256(Encoding.UTF8.GetBytes("AWS4" + secretAccessKey), "11111111");
            var kRegion = HmacSha256(kDate, region);
            var kService = HmacSha256(kRegion, "ses");
            var kTerminal = HmacSha256(kService, "aws4_request");
            var kMessage = HmacSha256(kTerminal, message);

            // Prepend version byte to the signature
            var signatureAndVersion = new byte[1 + kMessage.Length];
            signatureAndVersion[0] = version;
            Array.Copy(kMessage, 0, signatureAndVersion, 1, kMessage.Length);

            return Convert.ToBase64String(signatureAndVersion);
        }

        private static byte[] HmacSha256(byte[] key, string data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            }
        }
    }
}

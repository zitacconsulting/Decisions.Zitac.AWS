using Decisions.Zitac.AWS.Authentication;
using Decisions.Zitac.AWS.Settings;
using DecisionsFramework;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.Flow.CoreSteps;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.Properties.Attributes;
using DecisionsFramework.ServiceLayer.Services.Projects;

namespace Decisions.Zitac.AWS.Steps
{
    /// <summary>
    /// Common credential/region handling for steps that call AWS. Same model as Decisions.Kinesis:
    /// with "Override Settings" checked the step uses its own connection, otherwise the project's
    /// Zitac AWS settings, falling back to the system settings (see ZitacAWSSettings.GetConnection).
    /// </summary>
    [Writable]
    public abstract class BaseAwsStep : BaseFlowAwareStep, ISyncStep, IDataConsumer, IDataProducer, IValidationSource
    {
        protected const string AWS_CATEGORY = "AWS Settings";
        protected const string CREDENTIALS_CATEGORY = "Credentials";
        protected const string INPUTS_CATEGORY = "Inputs";
        protected const string INPUT_ACCESS_KEY_ID = "Access Key ID";
        protected const string INPUT_SECRET_ACCESS_KEY = "Secret Access Key";
        protected const string OUTCOME_DONE = "Done";
        protected const string OUTCOME_ERROR = "Error";
        protected const string OUTPUT_ERROR_MESSAGE = "Error Message";

        [WritableValue]
        protected bool overrideSettings;

        [WritableValue]
        protected AuthenticationMethod authenticationMethod = AuthenticationMethod.AWSDefaultCredentials;

        [WritableValue]
        protected string region;

        [WritableValue]
        protected bool assumeRole;

        [WritableValue]
        protected string roleArn;

        [WritableValue]
        protected string externalId;

        [WritableValue]
        protected string roleSessionName;

        [WritableValue]
        protected int sessionDurationMinutes = AwsConnection.DEFAULT_SESSION_DURATION_MINUTES;

        [PropertyClassification(0, "Override Settings", AWS_CATEGORY)]
        public bool OverrideSettings
        {
            get { return overrideSettings; }
            set
            {
                overrideSettings = value;
                OnPropertyChanged(nameof(OverrideSettings));
                OnPropertyChanged(nameof(InputData));
            }
        }

        [PropertyClassification(1, "Connection Info", AWS_CATEGORY)]
        [InfoOrWarningEditor(false, null, true)]
        [BooleanPropertyHidden(nameof(OverrideSettings), true)]
        public string ConnectionNote
        {
            get { return "Uses the project's AWS settings, or System > Settings > Zitac AWS Settings. Tick Override Settings to use another connection."; }
            set { }
        }

        [PropertyClassification(new[] { CREDENTIALS_CATEGORY }, "Credentials Info", 0)]
        [InfoOrWarningEditor(false, "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html", true)]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        [PropertyHiddenByValue(nameof(AuthenticationMethod), AuthenticationMethod.AccessKeys, false)]
        public string CredentialsNote
        {
            get { return "Avoid constant keys: they are saved in the flow. Prefer shared settings or an IAM role."; }
            set { }
        }

        [PropertyClassification(1, "AWS Region", AWS_CATEGORY)]
        [SelectStringEditor(nameof(RegionOptions))]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        public string Region
        {
            get { return region; }
            set
            {
                region = value;
                OnPropertyChanged(nameof(Region));
            }
        }

        [PropertyHidden]
        public string[] RegionOptions => AwsHelper.AllRegions;

        [PropertyClassification(2, "Authentication Method", AWS_CATEGORY)]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        public AuthenticationMethod AuthenticationMethod
        {
            get { return authenticationMethod; }
            set
            {
                authenticationMethod = value;
                OnPropertyChanged(nameof(AuthenticationMethod));
                OnPropertyChanged(nameof(InputData));
            }
        }

        [PropertyClassification(3, "Assume Role", AWS_CATEGORY)]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        public bool AssumeRole
        {
            get { return assumeRole; }
            set
            {
                assumeRole = value;
                OnPropertyChanged(nameof(AssumeRole));
            }
        }

        [PropertyClassification(4, "Role ARN", AWS_CATEGORY)]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public string RoleArn
        {
            get { return roleArn; }
            set { roleArn = value; OnPropertyChanged(nameof(RoleArn)); }
        }

        [PropertyClassification(5, "External ID (optional)", AWS_CATEGORY)]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public string ExternalId
        {
            get { return externalId; }
            set { externalId = value; OnPropertyChanged(nameof(ExternalId)); }
        }

        [PropertyClassification(6, "Role Session Name (optional)", AWS_CATEGORY)]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public string RoleSessionName
        {
            get { return roleSessionName; }
            set { roleSessionName = value; OnPropertyChanged(nameof(RoleSessionName)); }
        }

        [PropertyClassification(7, "Session Duration (minutes)", AWS_CATEGORY)]
        [BooleanPropertyHidden(nameof(OverrideSettings), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public int SessionDurationMinutes
        {
            get { return sessionDurationMinutes; }
            set { sessionDurationMinutes = value; OnPropertyChanged(nameof(SessionDurationMinutes)); }
        }

        public DataDescription[] InputData
        {
            get
            {
                var inputs = new List<DataDescription>();
                if (OverrideSettings && AuthenticationMethod == AuthenticationMethod.AccessKeys)
                {
                    inputs.Add(new DataDescription(typeof(string), INPUT_ACCESS_KEY_ID) { Categories = new[] { CREDENTIALS_CATEGORY } });
                    inputs.Add(new DataDescription(typeof(string), INPUT_SECRET_ACCESS_KEY) { Categories = new[] { CREDENTIALS_CATEGORY } });
                }
                inputs.AddRange(StepInputs);
                return inputs.ToArray();
            }
        }

        protected abstract IEnumerable<DataDescription> StepInputs { get; }

        protected abstract DataDescription[] DoneOutputs { get; }

        public override OutcomeScenarioData[] OutcomeScenarios => new[]
        {
            new OutcomeScenarioData(OUTCOME_DONE, DoneOutputs),
            new OutcomeScenarioData(OUTCOME_ERROR, new DataDescription(typeof(string), OUTPUT_ERROR_MESSAGE))
        };

        public ResultData Run(StepStartData data)
        {
            try
            {
                AwsConnection connection = ResolveConnection(data);
                connection.Validate();
                return new ResultData(OUTCOME_DONE, RunStep(data, connection));
            }
            catch (Exception ex)
            {
                return new ResultData(OUTCOME_ERROR, new Dictionary<string, object>
                {
                    { OUTPUT_ERROR_MESSAGE, AwsHelper.DescribeException(ex) }
                });
            }
        }

        protected abstract Dictionary<string, object> RunStep(StepStartData data, AwsConnection connection);

        protected AwsConnection ResolveConnection(StepStartData data)
        {
            if (!OverrideSettings)
                return ZitacAWSSettings.GetConnection(GetProjectId());

            var connection = new AwsConnection
            {
                Region = region,
                AuthenticationMethod = AuthenticationMethod,
                AssumeRole = assumeRole,
                RoleArn = roleArn,
                ExternalId = externalId,
                RoleSessionName = roleSessionName,
                SessionDurationMinutes = SessionDurationMinutes
            };
            if (AuthenticationMethod == AuthenticationMethod.AccessKeys)
            {
                connection.AccessKeyId = data.Data[INPUT_ACCESS_KEY_ID] as string;
                connection.SecretAccessKey = data.Data[INPUT_SECRET_ACCESS_KEY] as string;
            }
            return connection;
        }

        protected string GetProjectId()
        {
            string folderId = Flow?.FolderId;
            return string.IsNullOrEmpty(folderId) ? null : ProjectUtility.GetEntityProjectId(folderId, true, false);
        }

        public virtual ValidationIssue[] GetValidationIssues()
        {
            var issues = new List<ValidationIssue>();

            if (!OverrideSettings)
            {
                try
                {
                    if (string.IsNullOrEmpty(ZitacAWSSettings.GetConnection(GetProjectId()).Region))
                        issues.Add(new ValidationIssue(this, "No AWS Region is configured in the Zitac AWS settings (project or system). Configure them or check Override Settings.", "", BreakLevel.Warning, nameof(OverrideSettings)));
                }
                catch
                {
                    // Settings not reachable at design time; checked again at runtime.
                }
                return issues.ToArray();
            }

            if (string.IsNullOrEmpty(region))
                issues.Add(new ValidationIssue(this, "AWS Region must be selected", "", BreakLevel.Fatal, nameof(Region)));

            if (assumeRole && string.IsNullOrWhiteSpace(roleArn))
                issues.Add(new ValidationIssue(this, "Role ARN is required when Assume Role is enabled", "", BreakLevel.Fatal, nameof(RoleArn)));

            if (assumeRole && (SessionDurationMinutes < 15 || SessionDurationMinutes > 720))
                issues.Add(new ValidationIssue(this, "Session Duration must be between 15 and 720 minutes", "", BreakLevel.Fatal, nameof(SessionDurationMinutes)));

            return issues.ToArray();
        }
    }
}

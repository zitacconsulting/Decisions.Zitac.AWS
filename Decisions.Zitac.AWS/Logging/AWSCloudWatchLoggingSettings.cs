using System.Runtime.Serialization;
using Decisions.Zitac.AWS.Authentication;
using Decisions.Zitac.AWS.Settings;
using Decisions.Zitac.AWS.Steps;
using DecisionsFramework;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.Properties.Attributes;
using DecisionsFramework.ServiceLayer;
using DecisionsFramework.Utilities.Logging;

namespace Decisions.Zitac.AWS.Logging
{
    /// <summary>
    /// System > Settings > Logging Settings > Zitac AWS CloudWatch.
    /// Uses the system-level Zitac AWS Settings unless "Use Separate AWS Connection for Logging" is checked.
    /// </summary>
    [DataContract]
    public class AWSCloudWatchLoggingSettings : AbstractSinkSetting
    {
        private bool overrideAwsSettings;
        private string awsRegion;
        private AuthenticationMethod authenticationMethod = AuthenticationMethod.AWSDefaultCredentials;
        private bool assumeRole;
        private string logGroupPath = LogGroupResolver.DEFAULT_LOG_GROUP_PATH;
        private string accessKeyId;
        private string secretAccessKey;
        private string roleArn;
        private string externalId;
        private bool onlyLogSteps;
        private bool separateLogGroupPerProject;
        private bool compactLogFormat = true;

        private const string ROUTING_CATEGORY = "Log Routing";
        private const string FORMAT_CATEGORY = "Log Format";

        public override string Name => "Zitac AWS CloudWatch";

        [PropertyClassification(0, "Only Send Entries From \"Log\" Steps", ROUTING_CATEGORY)]
        [DataMember]
        public bool OnlyLogSteps
        {
            get { return onlyLogSteps; }
            set { onlyLogSteps = value; OnPropertyChanged(nameof(OnlyLogSteps)); }
        }

        [PropertyClassification(1, "About Only Send Entries From \"Log\" Steps", ROUTING_CATEGORY)]
        [InfoOrWarningEditor(false, null, true)]
        public string OnlyLogStepsHelp
        {
            get { return "Only messages from \"Log\" steps in flows are sent, not Decisions' system logging."; }
            set { }
        }

        [PropertyClassification(2, "One Log Group per Project", ROUTING_CATEGORY)]
        [BooleanPropertyHidden(nameof(OnlyLogSteps), false)]
        [DataMember]
        public bool SeparateLogGroupPerProject
        {
            get { return separateLogGroupPerProject; }
            set { separateLogGroupPerProject = value; OnPropertyChanged(nameof(SeparateLogGroupPerProject)); }
        }

        [PropertyClassification(3, "About One Log Group per Project", ROUTING_CATEGORY)]
        [InfoOrWarningEditor(false, null, true)]
        [BooleanPropertyHidden(nameof(OnlyLogSteps), false)]
        public string PerProjectHelp
        {
            get
            {
                string prefix = LogGroupResolver.NormalizePath(LogGroupPath);
                return $"Each project logs to its own group, e.g. {prefix}MyProject.";
            }
            set { }
        }

        [PropertyClassification(0, "Compact Log Format", FORMAT_CATEGORY)]
        [DataMember]
        public bool CompactLogFormat
        {
            get { return compactLogFormat; }
            set { compactLogFormat = value; OnPropertyChanged(nameof(CompactLogFormat)); OnPropertyChanged(nameof(LogFormatHelp)); }
        }

        [PropertyClassification(1, "About Log Format", FORMAT_CATEGORY)]
        [InfoOrWarningEditor(false, null, true)]
        public string LogFormatHelp
        {
            get
            {
                return CompactLogFormat
                    ? "Flat JSON with Level, Message, Category, Account, flow name and tracking ids. Server and session details are left out."
                    : "Full Decisions JSON, including server, thread and session details.";
            }
            set { }
        }

        /// <summary>Only routes events from flows by project when both options are on.</summary>
        [PropertyHidden]
        public bool RouteByProject => OnlyLogSteps && SeparateLogGroupPerProject;

        // Persisted as LogGroupPath (kept for saved settings); shown as "Log Group Prefix".
        [PropertyClassification(1, "Log Group Prefix", SETTINGS_CATEGORY_NAME)]
        [DataMember]
        public string LogGroupPath
        {
            get { return logGroupPath; }
            set
            {
                logGroupPath = value;
                OnPropertyChanged(nameof(LogGroupPath));
                OnPropertyChanged(nameof(LogGroupPrefixHelp));
                OnPropertyChanged(nameof(PerProjectHelp));
            }
        }

        [PropertyClassification(2, "About Log Group Prefix", SETTINGS_CATEGORY_NAME)]
        [InfoOrWarningEditor(false, null, true)]
        public string LogGroupPrefixHelp
        {
            get
            {
                string prefix = LogGroupResolver.NormalizePath(LogGroupPath);
                return $"Slashes are added automatically. Logs go to {prefix}Decisions.Web.Core.";
            }
            set { }
        }

        [PropertyClassification(3, "Use Separate AWS Connection for Logging", SETTINGS_CATEGORY_NAME)]
        [DataMember]
        public bool OverrideAwsSettings
        {
            get { return overrideAwsSettings; }
            set { overrideAwsSettings = value; OnPropertyChanged(nameof(OverrideAwsSettings)); OnPropertyChanged(nameof(ConnectionHelp)); }
        }

        [PropertyClassification(4, "Connection", SETTINGS_CATEGORY_NAME)]
        [InfoOrWarningEditor(false, null, true)]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), true)]
        public string ConnectionHelp
        {
            get
            {
                return "Uses the AWS connection in System > Settings > Zitac AWS Settings.";
            }
            set { }
        }

        [PropertyClassification(5, "AWS Region", SETTINGS_CATEGORY_NAME)]
        [SelectStringEditor(nameof(RegionOptions))]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), false)]
        [DataMember]
        public string AWSRegion
        {
            get { return awsRegion; }
            set { awsRegion = value; OnPropertyChanged(nameof(AWSRegion)); }
        }

        [PropertyHidden]
        public string[] RegionOptions => AwsHelper.AllRegions;

        [PropertyClassification(6, "Authentication Method", SETTINGS_CATEGORY_NAME)]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), false)]
        [DataMember]
        public AuthenticationMethod AuthenticationMethod
        {
            get { return authenticationMethod; }
            set { authenticationMethod = value; OnPropertyChanged(nameof(AuthenticationMethod)); }
        }

        [PropertyClassification(7, "Access Key ID", SETTINGS_CATEGORY_NAME)]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), false)]
        [PropertyHiddenByValue(nameof(AuthenticationMethod), AuthenticationMethod.AccessKeys, false)]
        [DataMember]
        public string AccessKeyId
        {
            get { return accessKeyId; }
            set { accessKeyId = value; OnPropertyChanged(nameof(AccessKeyId)); }
        }

        [PropertyClassification(8, "Secret Access Key", SETTINGS_CATEGORY_NAME)]
        [PasswordText]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), false)]
        [PropertyHiddenByValue(nameof(AuthenticationMethod), AuthenticationMethod.AccessKeys, false)]
        [DataMember]
        public string SecretAccessKey
        {
            get { return secretAccessKey; }
            set { secretAccessKey = value; OnPropertyChanged(nameof(SecretAccessKey)); }
        }

        [PropertyClassification(9, "Assume Role", SETTINGS_CATEGORY_NAME)]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), false)]
        [DataMember]
        public bool AssumeRole
        {
            get { return assumeRole; }
            set { assumeRole = value; OnPropertyChanged(nameof(AssumeRole)); }
        }

        [PropertyClassification(10, "Role ARN", SETTINGS_CATEGORY_NAME)]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        [DataMember]
        public string RoleArn
        {
            get { return roleArn; }
            set { roleArn = value; OnPropertyChanged(nameof(RoleArn)); }
        }

        [PropertyClassification(11, "External ID (optional)", SETTINGS_CATEGORY_NAME)]
        [BooleanPropertyHidden(nameof(OverrideAwsSettings), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        [DataMember]
        public string ExternalId
        {
            get { return externalId; }
            set { externalId = value; OnPropertyChanged(nameof(ExternalId)); }
        }

        /// <summary>The connection logs are sent with: this sink's own, or the system Zitac AWS Settings.</summary>
        public AwsConnection GetConnection()
        {
            if (!OverrideAwsSettings)
                return ModuleSettingsAccessor<ZitacAWSSettings>.GetSettings().ToConnection();

            return new AwsConnection
            {
                Region = AWSRegion,
                AuthenticationMethod = AuthenticationMethod,
                AccessKeyId = AccessKeyId,
                SecretAccessKey = SecretAccessKey,
                AssumeRole = AssumeRole,
                RoleArn = RoleArn,
                ExternalId = ExternalId,
                RoleSessionName = "Decisions-CloudWatch-Logging"
            };
        }

        public override bool IsLoggerEnabled()
        {
            // With the system settings the region isn't known yet this early in boot; it is
            // resolved when the first batch is sent (see LazyCloudWatchLogsClient).
            return base.IsLoggerEnabled() && (!OverrideAwsSettings || !string.IsNullOrEmpty(AWSRegion));
        }

        /// <summary>
        /// Sink checks only apply when the sink is enabled (its own Is Enabled, or the global one when
        /// Use Global Settings is on), so a disabled sink can be saved unconfigured. They are all warnings,
        /// never blocking: Is Enabled lives in AbstractSinkSetting as a plain auto-property that raises no
        /// PropertyChanged, so the editor doesn't re-validate when it is toggled and the shown result can
        /// lag until another field changes.
        /// </summary>
        public override ValidationIssue[] GetValidationIssues()
        {
            var list = new List<ValidationIssue>(base.GetValidationIssues());

            if (!IsSinkEnabled())
                return list.ToArray();

            // Decisions only passes an event to a sink if its level is in Levels (or a matching Log Category
            // entry allows it): Log.IncludeLog. With neither, the sink silently receives nothing.
            if (!UseGlobalSetting && (Levels == null || Levels.Length == 0) && (LogCategorySettings == null || LogCategorySettings.Length == 0))
                list.Add(new ValidationIssue(this, "No log levels are selected, so nothing will be sent to CloudWatch. Select the levels to send (for \"Log\" steps, include the level those steps use), or check 'Use Global Settings'.", "", BreakLevel.Warning, nameof(Levels)));

            if (!OverrideAwsSettings)
            {
                try
                {
                    if (string.IsNullOrEmpty(ModuleSettingsAccessor<ZitacAWSSettings>.GetSettings().Region))
                        list.Add(new ValidationIssue(this, "No AWS Region is configured in System > Settings > Zitac AWS Settings", "", BreakLevel.Warning, nameof(OverrideAwsSettings)));
                }
                catch
                {
                    // Settings not readable here; the sink reports connection problems when sending.
                }
                return list.ToArray();
            }

            if (string.IsNullOrEmpty(AWSRegion))
                list.Add(new ValidationIssue(this, "AWS Region is required", "", BreakLevel.Warning, nameof(AWSRegion)));

            if (AuthenticationMethod == AuthenticationMethod.AccessKeys)
            {
                if (string.IsNullOrEmpty(AccessKeyId))
                    list.Add(new ValidationIssue(this, "When using Access Keys, Access Key ID is required", "", BreakLevel.Warning, nameof(AccessKeyId)));
                if (string.IsNullOrEmpty(SecretAccessKey))
                    list.Add(new ValidationIssue(this, "When using Access Keys, Secret Access Key is required", "", BreakLevel.Warning, nameof(SecretAccessKey)));
            }

            if (AssumeRole && string.IsNullOrEmpty(RoleArn))
                list.Add(new ValidationIssue(this, "Role ARN is required when Assume Role is enabled", "", BreakLevel.Warning, nameof(RoleArn)));

            return list.ToArray();
        }

        private bool IsSinkEnabled()
        {
            try
            {
                // AbstractSinkSetting.IsLoggerEnabled: Is Enabled of this sink, or of the global setting.
                return base.IsLoggerEnabled();
            }
            catch
            {
                return IsEnabled;
            }
        }
    }
}

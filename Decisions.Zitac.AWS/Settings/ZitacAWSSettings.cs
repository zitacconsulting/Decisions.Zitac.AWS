using System.ComponentModel;
using Decisions.Zitac.AWS.Authentication;
using Decisions.Zitac.AWS.Steps;
using DecisionsFramework;
using DecisionsFramework.Data.ORMapper;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Projects.Dependency;
using DecisionsFramework.Design.Properties;
using DecisionsFramework.Design.Properties.Attributes;
using DecisionsFramework.ServiceLayer;
using DecisionsFramework.ServiceLayer.Actions;
using DecisionsFramework.ServiceLayer.Actions.Common;
using DecisionsFramework.ServiceLayer.Services.Accounts;
using DecisionsFramework.ServiceLayer.Services.Administration;
using DecisionsFramework.ServiceLayer.Services.Folder;
using DecisionsFramework.ServiceLayer.Services.Projects.Settings;
using DecisionsFramework.ServiceLayer.Utilities;

namespace Decisions.Zitac.AWS.Settings
{
    /// <summary>
    /// Shared AWS connection. One system-wide instance (System > Settings > Zitac AWS Settings)
    /// plus one per project that depends on this module (project > Integrations > AWS), which
    /// either inherits the system instance or overrides it.
    ///
    /// Decisions 9.x only (built against the 9.x SDK). 9.x stores project instances as ORM entities in
    /// the "&lt;projectId&gt;.zitac.aws" folder (hence RestrictEntityFolder's suffix, same pattern as
    /// BaseMqSettings). 10.x changed this to JSON files keyed by a ProjectId property, with a different
    /// ProjectSettingsAccessor.SaveSettings signature and an Edit action provided by the base class;
    /// see DecisionsKB notes/module-settings.md before porting.
    /// </summary>
    [RestrictEntityFolder("SETTINGS_SYSTEM_FOLDER", false, PROJECT_FOLDER_SUFFIX)]
    public class ZitacAWSSettings : AbstractModuleDependentSettings, INotifyPropertyChanged, IValidationSource
    {
        // Must equal the ModuleName in the packaged Module.json (see build.proj).
        public const string MODULE_NAME = "Decisions.Zitac.AWS";
        public const string PROJECT_FOLDER_SUFFIX = "zitac.aws";
        private const string CATEGORY = "AWS Connection";

        private bool overrideSystemSettings;
        private string region;
        private AuthenticationMethod authenticationMethod = AuthenticationMethod.AWSDefaultCredentials;
        private bool assumeRole;
        private string accessKeyId;
        private string secretAccessKey;
        private string roleArn;
        private string externalId;
        private string roleSessionName;
        private int sessionDurationMinutes = AwsConnection.DEFAULT_SESSION_DURATION_MINUTES;

        public event PropertyChangedEventHandler PropertyChanged;

        public ZitacAWSSettings()
        {
            EntityName = "Zitac AWS Settings";
        }

        public override string ModuleName => MODULE_NAME;

        [PropertyHidden]
        public bool IsProjectSettings => !string.IsNullOrEmpty(GetProjectId());

        [PropertyHidden]
        public bool ShowConnection => !IsProjectSettings || OverrideSystemSettings;

        [PropertyClassification(0, "About", CATEGORY)]
        [InfoOrWarningEditor(false, null, true)]
        public string Help
        {
            get
            {
                return IsProjectSettings
                    ? "Used by this project's Zitac AWS steps. Tick Override System Settings to use a different connection."
                    : "Default AWS connection for Zitac AWS steps and CloudWatch logging. Projects can override it. Prefer AWSDefaultCredentials (IAM role) over access keys.";
            }
            set { }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(1, "Override System Settings", CATEGORY)]
        [BooleanPropertyHidden(nameof(IsProjectSettings), false)]
        public bool OverrideSystemSettings
        {
            get { return overrideSystemSettings; }
            set
            {
                overrideSystemSettings = value;
                OnPropertyChanged(nameof(OverrideSystemSettings));
                OnPropertyChanged(nameof(ShowConnection));
            }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(2, "AWS Region", CATEGORY)]
        [SelectStringEditor(nameof(RegionOptions))]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
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

        [ORMField]
        [WritableValue]
        [PropertyClassification(3, "Authentication Method", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        public AuthenticationMethod AuthenticationMethod
        {
            get { return authenticationMethod; }
            set
            {
                authenticationMethod = value;
                OnPropertyChanged(nameof(AuthenticationMethod));
            }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(4, "Access Key ID", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        [PropertyHiddenByValue(nameof(AuthenticationMethod), AuthenticationMethod.AccessKeys, false)]
        public string AccessKeyId
        {
            get { return accessKeyId; }
            set { accessKeyId = value; OnPropertyChanged(nameof(AccessKeyId)); }
        }

        [ORMField(4000, typeof(FixedLengthStringFieldConverter))]
        [WritableValue]
        [PasswordText]
        [PropertyClassification(5, "Secret Access Key", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        [PropertyHiddenByValue(nameof(AuthenticationMethod), AuthenticationMethod.AccessKeys, false)]
        public string SecretAccessKey
        {
            get { return secretAccessKey; }
            set { secretAccessKey = value; OnPropertyChanged(nameof(SecretAccessKey)); }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(6, "Assume Role", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        public bool AssumeRole
        {
            get { return assumeRole; }
            set
            {
                assumeRole = value;
                OnPropertyChanged(nameof(AssumeRole));
            }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(7, "Role ARN", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public string RoleArn
        {
            get { return roleArn; }
            set { roleArn = value; OnPropertyChanged(nameof(RoleArn)); }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(8, "External ID (optional)", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public string ExternalId
        {
            get { return externalId; }
            set { externalId = value; OnPropertyChanged(nameof(ExternalId)); }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(9, "Role Session Name (optional)", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public string RoleSessionName
        {
            get { return roleSessionName; }
            set { roleSessionName = value; OnPropertyChanged(nameof(RoleSessionName)); }
        }

        [ORMField]
        [WritableValue]
        [PropertyClassification(10, "Session Duration (minutes)", CATEGORY)]
        [BooleanPropertyHidden(nameof(ShowConnection), false)]
        [BooleanPropertyHidden(nameof(AssumeRole), false)]
        public int SessionDurationMinutes
        {
            get { return sessionDurationMinutes; }
            set { sessionDurationMinutes = value; OnPropertyChanged(nameof(SessionDurationMinutes)); }
        }

        public AwsConnection ToConnection()
        {
            return new AwsConnection
            {
                Region = Region,
                AuthenticationMethod = AuthenticationMethod,
                AccessKeyId = AccessKeyId,
                SecretAccessKey = SecretAccessKey,
                AssumeRole = AssumeRole,
                RoleArn = RoleArn,
                ExternalId = ExternalId,
                RoleSessionName = RoleSessionName,
                SessionDurationMinutes = SessionDurationMinutes
            };
        }

        /// <summary>
        /// The connection a step in the given project should use: the project's own settings if it
        /// overrides them, otherwise the system settings. A null/empty projectId means system settings.
        /// </summary>
        public static AwsConnection GetConnection(string projectId)
        {
            if (!string.IsNullOrEmpty(projectId) && ModuleDependencyHelper.IsDependentModule(projectId, MODULE_NAME))
            {
                ZitacAWSSettings projectSettings = GetSettingsForProject(projectId);
                if (projectSettings.OverrideSystemSettings)
                    return projectSettings.ToConnection();
            }
            return ModuleSettingsAccessor<ZitacAWSSettings>.GetSettings().ToConnection();
        }

        public static ZitacAWSSettings GetSettingsForProject(string projectId)
        {
            // 9.x resolves a project instance's project through its folder, so the folder must exist
            // before the instance is first created.
            ZitacAWSDependencyInitializer.EnsureProjectFolder(projectId);
            return ProjectSettingsAccessor<ZitacAWSSettings>.GetSettings(projectId);
        }

        /// <summary>Copies the edited values onto the project's stored instance and saves it.</summary>
        public static void SaveSettingsForProject(string projectId, ZitacAWSSettings edited)
        {
            // The stored (cached) instance carries its id and project folder; the edited copy from the
            // dialog may not, so copy the values over instead of saving the copy.
            ZitacAWSSettings stored = GetSettingsForProject(projectId);
            stored.CopyConnectionFrom(edited);
            ProjectSettingsAccessor<ZitacAWSSettings>.SaveSettings(stored);
        }

        private void CopyConnectionFrom(ZitacAWSSettings other)
        {
            OverrideSystemSettings = other.OverrideSystemSettings;
            Region = other.Region;
            AuthenticationMethod = other.AuthenticationMethod;
            AccessKeyId = other.AccessKeyId;
            SecretAccessKey = other.SecretAccessKey;
            AssumeRole = other.AssumeRole;
            RoleArn = other.RoleArn;
            ExternalId = other.ExternalId;
            RoleSessionName = other.RoleSessionName;
            SessionDurationMinutes = other.SessionDurationMinutes;
        }

        public static BaseActionType CreateTestConnectionAction(Func<AwsConnection> getConnection)
        {
            return new DisplayHtmlTextAction("Test AWS Connection",
                "Authenticates with the configured settings and shows the resulting AWS identity",
                (userContext, entityId) => AwsHelper.TestConnection(getConnection()));
        }

        // 9.x's AbstractModuleSettings adds no Edit action; each settings class adds its own
        // (same permission check and action as BaseMqSettings / CommentModuleSettings).
        public override BaseActionType[] GetActions(AbstractUserContext userContext, EntityActionType[] types)
        {
            Account account = userContext.GetAccount();
            FolderPermission permission = FolderService.Instance.GetAccountEffectivePermission(new SystemUserContext(), EntityFolderID, account.AccountID);
            if (FolderPermission.CanAdministrate != (permission & FolderPermission.CanAdministrate)
                && account.GetUserRights<PortalAdministratorModuleRight>() == null
                && !account.IsAdministrator())
            {
                return Array.Empty<BaseActionType>();
            }

            string projectId = GetProjectId();
            return new BaseActionType[]
            {
                new EditEntityAction(GetType(), "Edit", "Edit the AWS connection")
                {
                    IsDefaultGridAction = true,
                    Order = -2
                },
                CreateTestConnectionAction(() => GetConnection(projectId))
            };
        }

        public override bool IsExportable()
        {
            return true;
        }

        public ValidationIssue[] GetValidationIssues()
        {
            var issues = new List<ValidationIssue>();
            if (!ShowConnection)
                return issues.ToArray();

            // An unconfigured system instance is valid; only check what has been started.
            if (string.IsNullOrWhiteSpace(Region))
            {
                if (IsProjectSettings)
                    issues.Add(new ValidationIssue(this, "AWS Region is required", "", BreakLevel.Fatal, nameof(Region)));
                return issues.ToArray();
            }

            if (AuthenticationMethod == AuthenticationMethod.AccessKeys)
            {
                if (string.IsNullOrWhiteSpace(AccessKeyId))
                    issues.Add(new ValidationIssue(this, "Access Key ID is required when using Access Keys", "", BreakLevel.Fatal, nameof(AccessKeyId)));
                if (string.IsNullOrWhiteSpace(SecretAccessKey))
                    issues.Add(new ValidationIssue(this, "Secret Access Key is required when using Access Keys", "", BreakLevel.Fatal, nameof(SecretAccessKey)));
            }

            if (AssumeRole)
            {
                if (string.IsNullOrWhiteSpace(RoleArn))
                    issues.Add(new ValidationIssue(this, "Role ARN is required when Assume Role is enabled", "", BreakLevel.Fatal, nameof(RoleArn)));
                if (SessionDurationMinutes < 15 || SessionDurationMinutes > 720)
                    issues.Add(new ValidationIssue(this, "Session Duration must be between 15 and 720 minutes", "", BreakLevel.Fatal, nameof(SessionDurationMinutes)));
            }

            return issues.ToArray();
        }

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}

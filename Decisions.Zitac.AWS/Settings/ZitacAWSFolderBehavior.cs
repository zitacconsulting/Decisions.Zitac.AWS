using System.Collections.Concurrent;
using DecisionsFramework;
using DecisionsFramework.Design.Projects.Dependency;
using DecisionsFramework.ServiceLayer;
using DecisionsFramework.ServiceLayer.Actions;
using DecisionsFramework.ServiceLayer.Actions.Common;
using DecisionsFramework.ServiceLayer.Services.Folder;
using DecisionsFramework.ServiceLayer.Services.Projects;
using DecisionsFramework.ServiceLayer.Utilities;

namespace Decisions.Zitac.AWS.Settings
{
    /// <summary>"AWS" folder under a project's Integrations folder, holding the project-level settings actions.</summary>
    public class ZitacAWSFolderBehavior : DefaultFolderBehavior
    {
        public override BaseActionType[] GetFolderActions(Folder folder, BaseActionType[] proposedActions, EntityActionType[] types)
        {
            var actions = new List<BaseActionType>(proposedActions ?? Array.Empty<BaseActionType>());
            string projectId = ProjectUtility.GetEntityProjectId(folder);
            if (string.IsNullOrEmpty(projectId))
                return actions.ToArray();

            actions.Add(new EditObjectAction(typeof(ZitacAWSSettings), "Configure AWS Settings",
                "Configure the AWS connection used by Zitac AWS steps in this project", null, "Configure AWS Settings",
                ZitacAWSSettings.GetSettingsForProject(projectId),
                (userContext, obj) => ZitacAWSSettings.SaveSettingsForProject(projectId, (ZitacAWSSettings)obj))
            {
                DisplayType = ActionDisplayType.Primary
            });
            actions.Add(ZitacAWSSettings.CreateTestConnectionAction(() => ZitacAWSSettings.GetConnection(projectId)));
            return actions.ToArray();
        }
    }

    public class ZitacAWSDependencyInitializer : IModuleDependencyInitializer, IInitializable
    {
        private static readonly Log log = new Log("Zitac AWS");

        public string ModuleName => ZitacAWSSettings.MODULE_NAME;

        private static readonly ConcurrentDictionary<string, bool> ensuredFolders = new ConcurrentDictionary<string, bool>();

        // Same id that 9.x derives for project settings instances from RestrictEntityFolder's suffix.
        public static string GetFolderId(string projectId) => projectId + "." + ZitacAWSSettings.PROJECT_FOLDER_SUFFIX;

        public static void EnsureProjectFolder(string projectId)
        {
            if (ensuredFolders.ContainsKey(projectId))
                return;
            FolderStructureHelper.CreateFolderIfNotExistsAndSendEvent(new SystemUserContext(),
                FolderStructureHelper.GetIntegrationsFolderId(projectId), GetFolderId(projectId), "AWS",
                typeof(ZitacAWSFolderBehavior).FullName);
            ensuredFolders[projectId] = true;
        }

        public void OnDependencyAdded(string projectId)
        {
            EnsureProjectFolder(projectId);
        }

        public void OnDependencyRemoved(string projectId)
        {
        }

        // Projects that already depended on the module before the folder existed get it at startup.
        public void Initialize()
        {
            try
            {
                foreach (string projectId in ProjectUtility.GetAllProjectIds().Where(id => ModuleDependencyHelper.IsDependentModule(id, ModuleName)))
                    EnsureProjectFolder(projectId);
            }
            catch (Exception ex)
            {
                log.Error(ex, "Could not create AWS folders for projects depending on " + ModuleName);
            }
        }
    }
}

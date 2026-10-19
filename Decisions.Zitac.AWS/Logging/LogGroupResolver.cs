using System.Collections.Concurrent;
using System.Text;
using DecisionsFramework.ServiceLayer.Services.Folder;
using DecisionsFramework.ServiceLayer.Services.Projects;
using Serilog.Events;

namespace Decisions.Zitac.AWS.Logging
{
    /// <summary>
    /// Decides which CloudWatch log group an event goes to: the main group, or with project routing
    /// the group of the project owning the flow that wrote it. "Log" steps (LogStep) put the running flow's
    /// definition id in the "FlowId" property (LogStep: FlowEngine.CurrentFlow.Id, or "Not Available").
    /// Project lookups run on the batching thread, never in the logging call, and are cached per flow.
    /// </summary>
    public class LogGroupResolver
    {
        public const string FLOW_ID_PROPERTY = "FlowId";
        private const int MAX_CACHED_FLOWS = 5000;

        private readonly string logGroupPath;
        private readonly bool routeByProject;
        private readonly ConcurrentDictionary<string, string> groupByFlowId = new ConcurrentDictionary<string, string>();

        public string MainLogGroup { get; }

        public const string DEFAULT_LOG_GROUP_PATH = "decisions";

        public LogGroupResolver(string logGroupPath, string mainLogGroupName, bool routeByProject)
        {
            this.logGroupPath = NormalizePath(logGroupPath);
            this.routeByProject = routeByProject;
            MainLogGroup = SanitizeGroupName(this.logGroupPath + mainLogGroupName);
        }

        /// <summary>"decisions", "/decisions", "decisions/" and "/decisions/" all become "/decisions/"; empty uses the default.</summary>
        public static string NormalizePath(string logGroupPath)
        {
            string trimmed = (logGroupPath ?? string.Empty).Trim().Trim('/');
            if (trimmed.Length == 0)
                trimmed = DEFAULT_LOG_GROUP_PATH;
            return "/" + trimmed + "/";
        }

        public static bool IsFromLogStep(LogEvent logEvent)
        {
            return logEvent.Properties.ContainsKey(FLOW_ID_PROPERTY);
        }

        public string Resolve(LogEvent logEvent)
        {
            if (!routeByProject)
                return MainLogGroup;

            string flowId = GetFlowId(logEvent);
            if (string.IsNullOrEmpty(flowId) || flowId == "Not Available")
                return MainLogGroup;

            if (groupByFlowId.TryGetValue(flowId, out string group))
                return group;

            if (groupByFlowId.Count >= MAX_CACHED_FLOWS)
                groupByFlowId.Clear();

            return groupByFlowId[flowId] = LookUpProjectGroup(flowId);
        }

        private string LookUpProjectGroup(string flowId)
        {
            try
            {
                Folder project = ProjectUtility.GetProjectOfEntity(flowId, true, false);
                string projectName = project?.EntityName;
                return string.IsNullOrWhiteSpace(projectName) ? MainLogGroup : SanitizeGroupName(logGroupPath + projectName);
            }
            catch
            {
                // Never let a lookup problem lose the event; it goes to the main group instead.
                return MainLogGroup;
            }
        }

        private static string GetFlowId(LogEvent logEvent)
        {
            return logEvent.Properties.TryGetValue(FLOW_ID_PROPERTY, out LogEventPropertyValue value) && value is ScalarValue scalar
                ? scalar.Value?.ToString()
                : null;
        }

        /// <summary>CloudWatch allows [.-_/#A-Za-z0-9], 1-512 characters.</summary>
        public static string SanitizeGroupName(string name)
        {
            var builder = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c == '_' || c == '/' || c == '#';
                builder.Append(allowed ? c : '_');
            }
            string sanitized = builder.ToString();
            if (sanitized.Length == 0)
                sanitized = "Decisions";
            return sanitized.Length > 512 ? sanitized.Substring(0, 512) : sanitized;
        }
    }
}

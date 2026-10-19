using System.Runtime.Serialization;

namespace Decisions.Zitac.AWS.Steps
{
    /// <summary>A CloudWatch log event as stored: the Message is the raw text (for Decisions logs, a JSON object).</summary>
    [DataContract]
    public class CloudWatchLogEvent
    {
        [DataMember]
        public DateTime Timestamp { get; set; }

        [DataMember]
        public string Message { get; set; }

        [DataMember]
        public string LogStreamName { get; set; }

        [DataMember]
        public string LogGroupName { get; set; }
    }
}

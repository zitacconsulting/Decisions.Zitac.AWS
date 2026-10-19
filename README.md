# Decisions Zitac AWS Module

> ⚠️ **Important:** Use this module at your own risk. See the **Disclaimer** section below.

## Overview

**Decisions Zitac AWS Module** connects the Decisions no-code automation platform to Amazon Web Services. It adds flow steps for calling AWS, one shared place to configure the AWS connection (system-wide, with optional per-project overrides), and a logging sink that sends Decisions logs to Amazon CloudWatch Logs, optionally with one log group per project.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [AWS Connection Settings](#aws-connection-settings)
- [Flow Steps](#flow-steps)
- [CloudWatch Logging](#cloudwatch-logging)
- [AWS Permissions](#aws-permissions)
- [Building from Source](#building-from-source)
- [Troubleshooting](#troubleshooting)
- [Upgrading from 1.x](#upgrading-from-1x)
- [Changelog](#changelog)
- [Disclaimer](#disclaimer)

## Features

### Shared AWS Connection
- Configure the AWS connection once in **System > Settings**, not in every step
- Per-project override: a project can use its own AWS account, region or role
- Per-step override for special cases
- Authentication with **Access Keys** or the **AWS default credentials** (IAM role, environment variables, ECS/EC2 instance credentials)
- **Assume Role** with optional External ID, session name and session duration; temporary credentials are cached and refreshed automatically
- **Test AWS Connection** action that shows which AWS account and identity you are connected as

### Flow Steps
- **Upload File to S3**: upload a file to a bucket and folder
- **Execute AWS Rest Method**: call any AWS REST API with a signed request (AWS Signature Version 4)
- **Generate SES SMTP Password**: derive the SMTP password for Amazon SES from an IAM secret access key
- **Get CloudWatch Log Events**: read log events from a CloudWatch log group, with filter, time range and paging

### CloudWatch Logging
- Send Decisions logs to Amazon CloudWatch Logs
- Optionally send only messages from **"Log"** steps in your flows
- Optionally use **one log group per project**, so each project can be monitored, secured and retained separately
- Settings changes take effect when you save, without restarting Decisions
- A logging problem never stops Decisions from starting or slows down flows

## Requirements

### Platform Requirements
- **Decisions Platform**: Version 9.26 – 9.32 (Decisions 9.x). Tested on 9.32.0.75864.
- **Decisions 10.x is not supported yet.** Version 10 changed how per-project settings are stored; the module will be updated when customers move to version 10.
- **Decisions.AWS module**: Required and installed automatically. The AWS SDK libraries this module uses ship with it.

### AWS Requirements
- An AWS account, and an IAM user or role the module can authenticate as (see [AWS Permissions](#aws-permissions))

## Installation

### Option 1: Install Pre-built Module
1. Download the compiled module (`Decisions.Zitac.AWS.zip`)
2. Log into the Decisions Portal
3. Navigate to **System > Administration > Features**
4. Click **Install Module**
5. Upload the module file
6. Restart the Decisions service if prompted

### Option 2: Build and Install
Build the module as described in [Building from Source](#building-from-source), then install the generated `Decisions.Zitac.AWS.zip` as in Option 1.

### Using the Module in a Project
In each project that should use the steps, add **Decisions.Zitac.AWS** as a module dependency: open the project, go to **Manage > Configuration > Dependencies**, click **Manage**, select **Decisions.Zitac.AWS** and click **Confirm**. This also creates an **AWS** folder under the project's **Integrations** folder, where the project's AWS settings live.

## Quick Start

1. Go to **System > Settings > Zitac AWS Settings** and click **Edit**.
2. Select the **AWS Region**, e.g. `eu-north-1`.
3. Select the **Authentication Method**:
   - **AWSDefaultCredentials** if Decisions runs in AWS with an IAM role (recommended; no keys to store)
   - **AccessKeys** to enter an Access Key ID and Secret Access Key
4. Save, then run **Test AWS Connection**. It should show your AWS account and identity.
5. In a flow, add **Integration > AWS > Zitac > Upload File to S3**. Leave **Override Settings** unticked, map the inputs, and run the flow.

## AWS Connection Settings

### Where the connection comes from

Each step uses the first of these that applies:

1. **The step itself**, if the step has **Override Settings** ticked
2. **The project's settings**, if the project has **Override System Settings** ticked
3. **The system settings** (System > Settings > Zitac AWS Settings)

### System settings
**System > Settings > Zitac AWS Settings.** Actions: **Edit** and **Test AWS Connection**.

### Project settings
**Project > Integrations > AWS.** Actions: **Configure AWS Settings** and **Test AWS Connection**. By default a project uses the system settings; tick **Override System Settings** to give the project its own connection.

### Connection fields

| Field | Description |
|-------|-------------|
| **AWS Region** | AWS region to connect to, e.g. `eu-north-1` (Stockholm) |
| **Authentication Method** | `AWSDefaultCredentials`: the AWS SDK's default credential chain (environment variables, shared credentials file, ECS task role, EC2 instance profile). `AccessKeys`: the Access Key ID and Secret Access Key below. |
| **Access Key ID** / **Secret Access Key** | IAM user access key (only with `AccessKeys`) |
| **Assume Role** | Use the credentials above to assume an IAM role, and use the role's temporary credentials |
| **Role ARN** | ARN of the role to assume, e.g. `arn:aws:iam::123456789012:role/DecisionsRole` |
| **External ID** (optional) | External ID required by the role's trust policy, if any |
| **Role Session Name** (optional) | Name shown in CloudTrail for the role session. Default: `Decisions-Zitac-AWS` |
| **Session Duration (minutes)** | 15–720 (max 12 hours, limited by the role's maximum session duration). Default: 60 |

> 🔒 **Security note:** Secret access keys are stored in the Decisions database as plain text. Where possible, run Decisions with an IAM role and use **AWSDefaultCredentials**, so no keys are stored at all.

## Flow Steps

All steps are found under **Integration > AWS > Zitac** in the flow designer. Each step shows short help texts next to its inputs, with links to the relevant AWS documentation, and optional inputs start as **Ignore**. AWS steps have two outcomes:
- **Done**: with the step's outputs
- **Error**: with an **Error Message** that includes the AWS error code and request ID when AWS returned one

### Step-level connection (Override Settings)
Tick **Override Settings** on a step to give that step its own connection instead of the project/system settings. The step then shows **AWS Region**, **Authentication Method** and the **Assume Role** fields. With **AccessKeys**, the step gets two extra inputs, **Access Key ID** and **Secret Access Key**, which can be mapped from flow data or constants.

### Upload File to S3

Uploads a file to an S3 bucket.

| Input | Description |
|-------|-------------|
| **S3 URI** | Bucket and optional folder: `s3://my-bucket/` or `s3://my-bucket/invoices/2026/` |
| **File Name** | Name of the object, appended to the folder, e.g. `invoice-1001.pdf` |
| **File Content** | The file's bytes |
| **Content Type** | MIME type, e.g. `application/pdf`. Optional (defaults to Ignore): when empty it is detected from the file name's extension, e.g. `.pdf` → `application/pdf`, `.xlsx` → the Excel type. Unknown extensions use `application/octet-stream`. |

| Output (Done) | Description |
|---------------|-------------|
| **Full S3 URI** | Location of the uploaded object, e.g. `s3://my-bucket/invoices/2026/invoice-1001.pdf` |
| **Content Type** | The content type the object was stored with (given or detected) |
| **ETag** | The object's ETag |
| **Version Id** | Object version, if versioning is enabled on the bucket |

The content type matters when people open the file from S3 in a browser (presigned URL, public bucket, CloudFront): with the right type a PDF or image opens in the browser, with `application/octet-stream` it is downloaded. Common content types: `text/plain`, `text/csv`, `application/json`, `application/pdf`, `image/png`, `image/jpeg`, `application/zip`, `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` (.xlsx).

### Execute AWS Rest Method

Sends a signed HTTP request to any AWS REST API.

| Input | Description |
|-------|-------------|
| **AWS Service Name** | The service's signing name, e.g. `sts`, `execute-api`, `s3`. Also used to build the default endpoint `https://<service>.<region>.amazonaws.com` |
| **API Endpoint Path** | Path and optional query string, e.g. `/?Action=GetCallerIdentity&Version=2011-06-15` |
| **HTTP Method** | GET, POST, PUT, DELETE or PATCH. Pre-filled with GET |
| **Request Body** | Request body. Optional (defaults to Ignore) |
| **Headers** | Extra HTTP headers, as a list of Key/Value pairs (Key = header name), e.g. `X-Amz-Target`. Optional (defaults to Ignore). A `Content-Type` header overrides the **Content Type** property. `Host`, `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256` and `X-Amz-Security-Token` are set by the request signing and can't be supplied. |

| Property | Description |
|----------|-------------|
| **Endpoint URL Override** (optional) | Use a different endpoint, e.g. `https://iam.amazonaws.com` for global services, an API Gateway URL such as `https://abc123.execute-api.eu-north-1.amazonaws.com/prod`, or a VPC endpoint |
| **Content Type** | Content type of the request body. Default: `application/json` |
| **Timeout (seconds)** | Default: 100 |

| Output (Done) | Description |
|---------------|-------------|
| **Response Content** | Response body |
| **Status Code** | HTTP status code |

A response with a non-success status code (4xx/5xx) goes to the **Error** outcome, with the status and response body in the error message.

**Example: who am I?** (needs no IAM permissions)
- AWS Service Name: `sts`
- API Endpoint Path: `/?Action=GetCallerIdentity&Version=2011-06-15`
- HTTP Method: `GET`

**Example: AWS JSON-protocol API** (DynamoDB, SQS, CloudWatch Logs and similar)
- AWS Service Name: `dynamodb`
- API Endpoint Path: `/`
- HTTP Method: `POST`
- Request Body: `{"TableName": "Orders"}`
- Headers: `X-Amz-Target` = `DynamoDB_20120810.DescribeTable`, `Content-Type` = `application/x-amz-json-1.0`

The `X-Amz-Target` value and content type for each action are in the service's API reference.

### Get CloudWatch Log Events

Reads log events from a CloudWatch log group, e.g. the logs Decisions sends with this module. Events are returned exactly as stored: for Decisions logs, **Message** is the JSON text of the entry; use **Deserialize JSON** in your flow to read its values.

| Input | Description |
|-------|-------------|
| **Log Group Name** | e.g. `/decisions/Decisions.Web.Core` or `/decisions/MyProject` |
| **Start Time** / **End Time** | Time range. Optional (defaults to Ignore = the last 60 minutes until now) |
| **Filter Pattern** | Optional. A [CloudWatch filter pattern](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html): a word such as `timeout`, or JSON conditions such as `{ $.Level = "Error" }` or `{ $.Properties.TopFlowTrackingId = "abc..." }` |
| **Log Stream Name Prefix** | Optional. Only streams starting with this, e.g. one server's host name |
| **Page Size** | Number of events per page, 1–10,000. Pre-filled with 100 |
| **Page Token** | Optional. The **Next Page Token** from the previous call, to get the next page |

| Output (Done) | Description |
|---------------|-------------|
| **Events** | List of events: **Timestamp** (UTC), **Message**, **Log Stream Name**, **Log Group Name** |
| **Next Page Token** | Pass it as **Page Token** to get the next page. Empty when there are no more events |
| **Has More Pages** | True when there is a next page |

Events are always returned **oldest first**; CloudWatch can't return newest first. To get recent events, narrow the time range (e.g. the last 15 minutes). To read everything, loop while **Has More Pages** is true, passing **Next Page Token** back in as **Page Token**.

### Generate SES SMTP Password

Converts an IAM user's Secret Access Key into the SMTP password used to send email through Amazon SES. This step doesn't call AWS and doesn't use the connection settings.

| Input / Property | Description |
|------------------|-------------|
| **Secret Access Key** (input) | Secret access key of the IAM user that will send email (needs `ses:SendRawEmail`) |
| **AWS Region** (property) | The SES region you will send through. The password is region-specific. |

| Output (Done) | Description |
|---------------|-------------|
| **SMTP Password** | Use it with the IAM user's Access Key ID as the SMTP user name |

## CloudWatch Logging

Configured under **System > Settings > Logging Settings > Zitac AWS CloudWatch**.

### Settings

| Setting | Description |
|---------|-------------|
| **Is Enabled** / **Levels** / **Log Categories** / **Use Global Settings** | Standard Decisions logging settings: which log levels and categories are sent. **At least one level must be selected** (or Use Global Settings ticked), otherwise nothing is sent. |
| **Log Group Prefix** | Start of the log group names, without slashes. Default: `decisions`, giving groups like `/decisions/Decisions.Web.Core`. `company/prod` gives `/company/prod/...` |
| **Use Separate AWS Connection for Logging** | Unticked: logs are sent with the system **Zitac AWS Settings**. Ticked: logging uses its own region, credentials and role, configured below it. |
| **Only Send Entries From "Log" Steps** | Only messages written by **Log** steps in flows (Flow Management > Error Handling > Log) are sent. Decisions' own system logging is not sent. |
| **One Log Group per Project** | Shown when the option above is ticked. Each project's messages go to their own log group named after the project, e.g. `/decisions/MyProject`. Messages from flows outside a project go to `/decisions/Decisions.Web.Core`. |

### Why one log group per project?
In CloudWatch, a log group is more than a folder:
- **Access control:** IAM policies can give a team read access to only their project's log group
- **Retention:** keep each project's logs for a different period
- **Alarms and metrics:** e.g. alert when a project logs more than 5 errors in 10 minutes
- **Forwarding:** send one project's logs to another system (Splunk, OpenSearch, Lambda) with a subscription filter
- **No extra cost:** CloudWatch charges for data, not per log group

Log groups and log streams are created automatically. Each server writes its own log stream (`<hostname>_<start time>_<id>`), so clustered servers never mix their entries.

### Flow tracking fields
Entries written from inside a running flow get three extra fields in CloudWatch (not in Decisions' own log file):

| Field | Description |
|-------|-------------|
| `Properties.TopFlowTrackingId` | ID of the top-level flow execution. The same for the whole run, including synchronous subflows, so one execution can be followed across flows. |
| `Properties.FlowTrackingId` | Full tracking ID of the flow or subflow that wrote the entry |
| `Properties.FlowName` | Name of the flow that wrote the entry |

Flows started asynchronously (e.g. "Run Flow Async") are separate executions with their own TopFlowTrackingId.

### Session IDs in logs (important)
Decisions adds the user's session to every log entry as `Properties.SessionId`. **By default this is the real session ID**, which can be used to call Decisions as that user while the session is active. Anyone who can read the logs, now including everyone with access to the CloudWatch log groups, could use it.

Turn on Decisions' **Obfuscate Session Id In Logs** setting on every server before sending logs to CloudWatch:
- `Settings.xml`: `<ObfuscateSessionIdInLogs>true</ObfuscateSessionIdInLogs>`
- or, for containers, the environment variable `DECISIONS_OBFUSCATESESSIONIDINLOGS=true`

Restart Decisions afterwards. Decisions then logs a SHA-256 hash of the session ID instead, in its own log file as well as in CloudWatch. The hash is the same for the same session on every server, so entries can still be grouped by session, but it can't be used to log in.

**Named sessions are permanent.** Flows and integrations that run with a named session (System > Security > Named Sessions) log a session ID like `NS-...` that never expires: it works until the named session is deleted, as the account it belongs to (often a service or admin account). If a plain named session ID has already reached the logs, delete the named session, create a new one and update the systems that use it.

`Properties.ClientSessionId` identifies the browser window's live-update connection and is not sensitive.

### Searching logs
Log entries are JSON. In **CloudWatch > Logs > Logs Insights**, every field can be shown as a column, filtered and sorted. For example, all entries of one execution:
```
fields @timestamp, Level, Properties.FlowName as Flow, MessageTemplate as Message, Properties.Category as Category
| filter Properties.TopFlowTrackingId = "PASTE-TRACKING-ID"
| sort @timestamp asc
```
Recent errors:
```
fields @timestamp, Properties.FlowName as Flow, MessageTemplate as Message
| filter Level = "Error"
| sort @timestamp desc
```

### Behavior when something is wrong
- Logs are sent in the background every 10 seconds, so flows never wait for CloudWatch.
- If sending fails (wrong credentials, no network), the sink retries with increasing delays (5 seconds up to 10 minutes). After repeated failures the oldest entries are dropped. At most 10,000 entries are kept in memory.
- A logging problem never stops Decisions from starting.

> ℹ️ This sink replaces the built-in **AWS CloudWatch** sink of the Decisions.AWS module. In Decisions 9.26–9.32 the built-in sink most likely cannot send any logs: Decisions.AWS ships an AWS SDK CloudWatch library (3.7) that is incompatible with the AWS SDK core (4.x) shipped with Decisions. This module talks to CloudWatch directly and doesn't depend on that library.

## AWS Permissions

Grant only what you use. Example policy for an IAM user or role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "UploadToS3",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    },
    {
      "Sid": "CloudWatchLogging",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:FilterLogEvents"],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/decisions/*",
        "arn:aws:logs:*:*:log-group:/decisions/*:*"
      ]
    }
  ]
}
```

| Feature | Permissions |
|---------|-------------|
| Test AWS Connection | None (`sts:GetCallerIdentity` is always allowed) |
| Upload File to S3 | `s3:PutObject` on the bucket |
| Execute AWS Rest Method | Whatever the called API requires |
| CloudWatch Logging | `logs:CreateLogStream`, `logs:PutLogEvents`, and `logs:CreateLogGroup` unless the groups are created in advance |
| Get CloudWatch Log Events | `logs:FilterLogEvents` on the log group |
| Assume Role | `sts:AssumeRole` on the role for the calling identity, and a trust policy on the role that allows that identity (with the External ID, if used) |

## Building from Source

### Prerequisites
- .NET 10 SDK
- CreateDecisionsModule Global Tool (`dotnet tool install --global CreateDecisionsModule-GlobalTool`)

The project compiles against the Decisions SDK (NuGet) and the DLLs in `lib/`. Those are copies of DLLs that already ship with Decisions 9.26 (AWS SDK, Serilog, Decisions.Logging). They are compile-only references and are never packaged into the module.

### Build Steps

#### On Linux/macOS:
```bash
chmod +x build_module.sh
./build_module.sh
```

#### Manual Build:
```bash
# 1. Publish the project
dotnet publish ./Decisions.Zitac.AWS/Decisions.Zitac.AWS.csproj --runtime linux-x64 --self-contained false --output ./Decisions.Zitac.AWS/bin -c Debug

# 2. Create the module package
dotnet msbuild build.proj -t:build_module
```

### Build Output
`Decisions.Zitac.AWS.zip` in the repository root, containing only `Decisions.Zitac.AWS.dll` and the module icon.

> ⚠️ Build the package with `build.proj` (or `build_module.sh`), not by calling `CreateDecisionsModule -buildmodule Decisions.Zitac.AWS` directly. The tool cuts the module name at the last dot, which would produce a module named `Decisions.Zitac`. `build.proj` passes `Decisions.Zitac.AWS.Module` and renames the zip, so the module is correctly named `Decisions.Zitac.AWS`.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Nothing arrives in CloudWatch | Check that **Is Enabled** is ticked and at least one **Level** is selected (or **Use Global Settings** is ticked). With **Only Send Entries From "Log" Steps**, the Log step's level must be among the selected levels. |
| Project log group doesn't appear | The flow must belong to a project, and the project must be using **Log** steps. Messages from flows outside a project go to the main group. |
| `UnrecognizedClientException` / "security token is invalid" | Wrong Access Key ID or Secret Access Key, or the key is deactivated. |
| `AccessDenied` | The identity lacks the permission; see [AWS Permissions](#aws-permissions). Run **Test AWS Connection** to see which identity is actually used (e.g. whether Assume Role is in effect). |
| `AccessDenied` when assuming a role | The role's trust policy doesn't allow the calling identity, the External ID doesn't match, or the identity lacks `sts:AssumeRole`. |
| `SignatureDoesNotMatch` with Execute AWS Rest Method | Check that **AWS Service Name** is the service's signing name, and that **Endpoint URL Override** points to that service. |
| Steps can't be found in the toolbox | Add **Decisions.Zitac.AWS** as a dependency of the project. |
| "No AWS Region is configured" warning on a step | Configure the region in the system or project settings, or tick **Override Settings** on the step. |

## Upgrading from 1.x

Version 2.0 is not backward compatible with 1.x:
1. **Module name changed** from `Decisions.Zitac` to `Decisions.Zitac.AWS`. Uninstall the old module, install the new one, and re-add **Decisions.Zitac.AWS** as a dependency in the projects that use it.
2. **Steps must be reconfigured.** New steps use the shared settings by default. To keep per-step keys as in 1.x, tick **Override Settings**, select **AccessKeys** and map **Access Key ID** / **Secret Access Key** again.
3. **Logging:** the separate `Decisions.Zitac.AWS.Logging` module is no longer needed; CloudWatch logging is part of this module.

## Changelog

### 2.0.0
- Shared AWS connection settings: system-wide, per-project override, and per-step override
- Assume Role support (External ID, session name, session duration) with cached, auto-refreshed credentials
- **Test AWS Connection** action
- New **Get CloudWatch Log Events** step with filter pattern, time range and paging
- CloudWatch logging merged into this module, rewritten to call CloudWatch Logs directly; options for "Log"-step-only logging and one log group per project; entries from flows carry TopFlowTrackingId, FlowTrackingId and FlowName
- Upload File to S3: fixed authentication with Access Keys; content type detected from the file name when not given; added Content Type, ETag and Version Id outputs
- Execute AWS Rest Method: fixed request signing for query strings, special characters and non-S3 services; added Headers input, Endpoint URL Override, Content Type, Timeout and Status Code; Request Body (JSON) renamed to Request Body
- Region lists now include every AWS region
- Clearer error messages, including AWS error code and request ID
- Module name corrected to `Decisions.Zitac.AWS`; targets Decisions 9.26–9.32

### 1.x
- Execute AWS Rest Method, Upload File to S3 and Generate SES SMTP Password steps with per-step credentials

## Disclaimer

This module is provided "as is" without warranties of any kind. Use it at your own risk. The authors, maintainers, and contributors disclaim all liability for any direct, indirect, incidental, special, or consequential damages, including data loss or service interruption, arising from the use of this software.

**Important Notes:**
- Always test in a non-production environment first
- Prefer IAM roles over stored access keys, and grant only the permissions you need
- Enable **Obfuscate Session Id In Logs** before sending logs to CloudWatch (see [Session IDs in logs](#session-ids-in-logs-important))
- Monitor AWS costs associated with CloudWatch Logs ingestion and storage
- This module is not officially supported by AWS or Decisions

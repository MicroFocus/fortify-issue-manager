# Fortify Issue Manager

This is a utility to find issues created by Fortify on Demand scans and create corresponding bugs in a bug tracker like `Jira` or `Octane`. Once the bugs are created they are linked back to the Fortify on Demand issue. Users can then click the `View Bug` button in Fortify on Demand to navigate to the corresponding bug.

### Fortify on Demand Configuration
You will need to configure the Fortify on Demand application to `Enable Bug Tracker Integration` and set `Bug Tracker` to `Other`. This can be done from the Fortify on Demand Applications view > Settings > Bug Tracker tab.

![Settings](images/FoDsettings.png)

### fortify-java-issue-manager

It can be used from another Java project by including the following dependency:

```xml
<dependency>
    <groupId>com.microfocus.security.automation.fortify</groupId>
    <artifactId>fortify-issue-manager</artifactId>
</dependency>
```

It makes the following `static` method available in the `FortifyIssueManager` class:

```java
public static boolean manageIssues(final boolean dryRun, final String scriptFile)
```

### fortify-java-issue-manager-cli

This modules provides a simple command-line interface which wraps the `manageIssues()` function.

    Usage: fortify-issue-manager [-d] -s=<scriptFile>
      -d, --dryRun
             If true, the tool lists the bug details but does not create them. Defaults to false.
      -s, --scriptFile=<scriptFile>
             Specifies the script file with the `getPayload` function to create the bug details

A javascript file that includes a `getPayload` function must be specified.

The `getPayload` function will be passed the following arguments:
- applicationId - The Fortify application ID
- applicationName - The Fortify application Name
- severity - The severity of the Fortify issue
- category - The category of the Fortify issue
- description - The description of the Fortify vulnerabilities in the category

The script should return the payload for creating a bug in a bug tracking application.  

Here is a sample script file [getPayload.js](./fortify-issue-manager/src/test/resources/getPayload.js).

### Required Configuration
The following environment variables must be set:
- `FORTIFY_AUTH_TYPE`  
    This property configures the Fortify on Demand authentication type.  
    It must be set to `basic` or `token`.

    If grant type is `basic` then the following environment variables must be set:
     - `FORTIFY_USERNAME`
     - `FORTIFY_PASSWORD`

    If grant type is `token` then the following environment variable must be set:
     - `FORTIFY_TOKEN`

- `FORTIFY_API_URL`  
    This property configures the Fortify on Demand api url

- `FORTIFY_ISSUE_URL`  
    This property configures the Fortify on Demand issue url

- `FORTIFY_APPLICATION_IDS`  
    This property is a comma separated list of Fortify on Demand application ids

- `FORTIFY_ISSUE_QUERY`  
    This property is a Fortify issue query expression used to filter which issues selected.  
    If specified, it will be combined with the `comments:!bugURL` filter (which selects issues that have not had a bug
    raised against them yet in the issue tracker).  
    If not specified, the following issue query expression is applied:  
    `comments:!bugURL audited:false [fortify priority order]:high [fortify priority order]:critical`
    which Fortify applies as:  
    `comments:!bugURL AND audited:false AND ([fortify priority order]:high OR [fortify priority order]:critical))`

- `TRACKER`  
    This property defines the issue tracker to use.
    Supported trackers: `JIRA`, `OCTANE`

- `TRACKER_USERNAME`  
    This property configures the issue tracker username

- `TRACKER_PASSWORD`  
    This property configures the issue tracker password

- `TRACKER_API_URL`  
    This property configures the issue tracker url

#### Octane required configuration
###### Note that the username and password must be generated for the shared_space and workspace

- `TRACKER_SHARED_SPACE_ID`  
  This property configures the octane shared space id.

- `TRACKER_WORKSPACE_ID`  
  This property configures the octane workspace id.

- `TRACKER_API_URL`  
    This property configures the issue tracker url

#### Logging
Set the `FORTIFY_ISSUE_MANAGER_LOG_LEVEL` environment variable to configure the log level. Default is `INFO`.

#### Note
Fortify on Demand field filters are specified as follows:  
Field name and value should be separated by a colon (:). Multiple fields should be separated by a plus (+). Multiple fields are treated as an AND condition.  
Example, `fieldname1:value+fieldname2:value`  
Multiple values for a field should be separated by a pipe (|).  
Multiple values for a field are treated as an OR condition.  
Example, `fieldname1:value1|value2`

### fortify-issue-manager-cli-image
This module builds a Docker image for the command-line interface, potentially allowing for simpler usage in some environments.

Here is an example command specific to Octane:

```
docker container run --rm \
    -e FORTIFY_GRANT_TYPE=password \
    -e FORTIFY_USERNAME=<Fortify on Demand username> \
    -e FORTIFY_PASSWORD=<Fortify on Demand password> \
    -e FORTIFY_TENANT=<Fortify on Demand tenant> \
    -e FORTIFY_SCOPE=<Fortify on Demand scope> \
    -e FORTIFY_API_URL=<Fortify on Demand API URL> \
    -e FORTIFY_ISSUE_URL=<Fortify on Demand issue URL> \
    -e FORTIFY_APPLICATION_IDS=<Comma separated list of application ids> \
    -e FORTIFY_RELEASE_FILTERS=<Delimited list of release field filters> \
    -e FORTIFY_ISSUE_FILTERS=<Delimited list of issue field filters> \
    -e TRACKER=<JIRA|OCTANE> \
    -e TRACKER_USERNAME=<username> \
    -e TRACKER_PASSWORD=<password> \
    -e TRACKER_API_URL=<URL> \
    -e TRACKER_SHARED_SPACE_ID=<id> \
    -e TRACKER_WORKSPACE_ID=<id> \
    -e HTTP_PROXY \
    -v $(pwd):/wd \
    microfocus/fortify-issue-manager \
    -s=/wd/getPayload.js
```

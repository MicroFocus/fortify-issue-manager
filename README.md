# Fortify Issue Manager

This is a utility to find issues created by Fortify scans and create corresponding bugs in a bug tracker like `Jira` or `Octane`. 
Once the bugs are created they are linked back to the Fortify issue via a comment on the Fortify issue using the format `bugURL: http://example.com`.

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
- `FORTIFY_TOKEN`  
    This property configures the Fortify auth token that will be placed in the `Authorization` header.

- `FORTIFY_URL`  
    This property configures the Fortify url

- `FORTIFY_APPLICATION_IDS`  
    This property is a comma separated list of Fortify application ids

- `FORTIFY_RELEASE_IDS`  
  This property is a comma separated list of Fortify release/version ids

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

### fortify-issue-manager-cli-image
This module builds a Docker image for the command-line interface, potentially allowing for simpler usage in some environments.

Here is an example command specific to Octane:

```
docker container run --rm \
    -e FORTIFY_TOKEN=<Fortify token> \
    -e FORTIFY_URL=<Fortify URL> \
    -e FORTIFY_APPLICATION_IDS=<Comma separated list of application ids> \
    -e FORTIFY_RELEASE_IDS=<Comma separated list of application ids> \
    -e FORTIFY_ISSUE_QUERY=<Fortify issue query expression> \
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

# Fortify Issue Manager

This is a utility to find issues created by Fortify on Demand scans and create corresponding bugs in a bug tracker like Jira. Once the bugs are created they are linked back to the Fortify on Demand issue.

It can be used from another Java project by including the following dependency:

```xml
<dependency>
    <groupId>com.microfocus.security.automation.fortify</groupId>
    <artifactId>fortify-issue-manager</artifactId>
</dependency>
```

It makes the following `static` method available in the `FortifyIssueManager` class:

```java
public static boolean manageIssues(final String scriptFile)
```

### fortify-java-issue-manager-cli

This modules provides a simple command-line interface which wraps the `manageIssues()` function.

    Usage: fortify-issue-manager -s=<scriptFile>
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

### Configuration
The following environment variables must be set:
- `FORTIFY_GRANT_TYPE`
    This property configures the Fortify on Demand authentication grant type. It must be set to `client_credentials` or `password`.
    If grant type is `client_credentials` then `FORTIFY_CLIENT_ID` and `FORTIFY_CLIENT_SECRET` must be set.
    If grant type is `password` then `FORTIFY_TENANT`, `FORTIFY_USERNAME` and `FORTIFY_PASSWORD` must be set.
- `FORTIFY_SCOPE`
    This property configures the Fortify on Demand scope. Example: api-tenant
- `FORTIFY_API_URL`
    This property configures the Fortify on Demand api url
- `FORTIFY_ISSUE_URL`
    This property configures the Fortify on Demand issue url
- `FORTIFY_APPLICATION_IDS`
    This property is a comma separated list of Fortify on Demand application ids
- `BUG_TRACKER_USERNAME`
    This property configures the bug tracker username
- `BUG_TRACKER_PASSWORD`
    This property configures the bug tracker password
- `BUG_TRACKER_API_URL`
    This property configures the bug tracker url

Set the `FORTIFY_ISSUE_MANAGER_LOG_LEVEL` environment variable to configure the log level. Default is `INFO`.

### fortify-issue-manager-cli-image
This module builds a Docker image for the command-line interface, potentially allowing for simpler usage in some environments.

Here is an example command:

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
    -e BUG_TRACKER_USERNAME=<Bug tracker username> \
    -e BUG_TRACKER_PASSWORD=<Bug tracker password> \
    -e BUG_TRACKER_API_URL=<Bug tracker URL> \
    -e HTTP_PROXY \
    -v $(pwd):/wd \
    microfocus/fortify-issue-manager \
    -s=/wd/getPayload.js
```

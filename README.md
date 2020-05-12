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
public static void manageIssues(final String scriptFile)
```

### fortify-java-issue-manager-cli

This modules provides a simple command-line interface which wraps the `manageIssues()` function.

    Usage: fortify-issue-manager -s=<scriptFile>
      -s, --scriptFile=<scriptFile>
             Specifies the script file with the `getPayload` function to create the bug details

The configuration file that includes connection details to Fortify on Demand and the bug tracker must be specified.

### fortify-issue-manager-cli-image
This module builds a Docker image for the command-line interface, potentially allowing for simpler usage in some environments.

Here is an example command:

```
docker container run --rm \
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
    -v $(pwd):/wd \
    cafapi/fortify-issue-manager:<VERSION-NUMBER> \
    -s=/wd/getPayload.js
```

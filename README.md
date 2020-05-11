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
public static void manageIssues(final String configFile)
```

### fortify-java-issue-manager-cli

This modules provides a simple command-line interface which wraps the `manageIssues()` function.

    Usage: fortify-issue-manager -c=<configFile>
      -c, --configFile=<configFile>
             Specifies the configuration file

The configuration file that includes connection details to Fortify on Demand and the bug tracker must be specified.

### fortify-issue-manager-cli-image
This module builds a Docker image for the command-line interface, potentially allowing for simpler usage in some environments.

To pull the image, first ensure that you have logged into the Docker registry using your [swinfra.net](http://domaininfo.swinfra.net/) account credentials:

```
docker login saas-docker.svsartifactory.swinfra.net
```

Here is an example command:

```
docker container run --rm \
    saas-docker.svsartifactory.swinfra.net/sepg/fortify-issue-manager:<VERSION-NUMBER> \
    -c=/fortifyIssueManagerConfig.yaml
```

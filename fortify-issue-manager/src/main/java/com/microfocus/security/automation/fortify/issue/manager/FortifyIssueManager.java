/*
 * Copyright 2020-2023 Open Text.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.microfocus.security.automation.fortify.issue.manager;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import com.microfocus.security.automation.fortify.issue.manager.models.Release;
import com.microfocus.security.automation.fortify.issue.tracker.BugTrackerException;
import com.microfocus.security.automation.fortify.issue.tracker.BugTrackerFactory;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microfocus.security.automation.fortify.issue.manager.models.Application;
import com.microfocus.security.automation.fortify.issue.manager.models.Category;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;
import com.microfocus.security.automation.fortify.issue.manager.utils.JavaScriptFunctions;

public final class FortifyIssueManager
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyIssueManager.class);
   // private final String FORTIFY_ISSUE_LINK_FORMAT = "%s/ssc/html/ssc/version/%s/audit?q=[instance id]:";
   // private final String FORTIFY_ISSUE_LINK_FORMAT = "%s/ssc/html/ssc/version/%s/audit?q=%5Binstance%%20id%5D%%3A";

    //   https://fortifyhub.otxlab.net/ssc/html/ssc/version/1301/audit?q=%5Binstance%20id%5D%3A265F3A8F2181596CCB92EBA2602D099F%20
    //   "issueInstanceId" : "24EEEC2639498E6426DDAECC003F1B10",
    //https://fortifyhub.otxlab.net/ssc/html/ssc/version/1301/audit?issue=05861F0EB70D93D3497FBC517BE607AC

    private final FortifyRequestHandler fortifyRequestHandler;
    private final BugTracker bugTracker;
    private final String[] applicationIds;
    private final String issueQuery;
    private final String issueUrl;
    private final boolean dryRun;
    private static boolean hasErrors;

    private FortifyIssueManager(
        final boolean dryRun,
        final FortifyClient client,
        final String[] applicationIds,
        final String issueQuery,
        final String issueUrl,
        final String targetTrackerName
    ) throws ConfigurationException {
        this.dryRun = dryRun;
        this.fortifyRequestHandler = new FortifyRequestHandler(client);
        this.bugTracker = BugTrackerFactory.getTracker(targetTrackerName);
        this.applicationIds = applicationIds;
        this.issueQuery = issueQuery;
        this.issueUrl = issueUrl;
    }

    /**
     * Create bugs for Fortify issues.
     *
     * @param dryRun If true, the tool lists the bug details but does not create them.
     * @param scriptFile Script file to create the bug payload
     * @return true if there were no errors when managing issues
     */
    public static boolean manageIssues(final boolean dryRun, final String scriptFile)
    {
        // Check that the required parameters have been specified
        if (Objects.isNull(scriptFile)) {
            throw new NullPointerException("Script file must be specified");
        }
        try {
            final FortifyIssueManagerConfiguration config = loadConfiguration();
            LOGGER.info("Managing Fortify issues. {}",
                    dryRun
                    ? "This is a dry run. No bugs will actually be created."
                    : "Bugs will be created and Fortify issues will be updated with the corresponding link to the bug.");
            final FortifySettings fortifySettings = config.getFortifySettings();
            final FortifyClient client = new FortifyClient(
                fortifySettings.getApiUrl(),
                fortifySettings.getUsername(),
                fortifySettings.getPassword(),
                fortifySettings.getToken(),
                fortifySettings.getAuthType(),
                fortifySettings.getProxySettings());

            final FortifyIssueManager issueManager = new FortifyIssueManager(
                dryRun, client,
                fortifySettings.getApplicationIds(),
                fortifySettings.getIssueQuery(),
                fortifySettings.getIssueUrl(),
                config.getBugTrackerName());
            issueManager.linkIssuesToBugTracker(scriptFile);
        } catch (final IOException | ScriptNotFoundException | ScriptException | FortifyAuthenticationException |
                       FortifyRequestException | NoSuchMethodException | ConfigurationException e) {
            LOGGER.error("Error managing Fortify issues", e);
            hasErrors = true;
        }
        LOGGER.info("Managing Fortify issues completed with {}", hasErrors ? "errors." : "no errors.");
        return !hasErrors;
    }

    private static FortifyIssueManagerConfiguration loadConfiguration() throws ConfigurationException
    {
        final Map<String, String> proxySettings = ConfigurationManager.getProxySetting("HTTP_PROXY");
        final List<String> configErrors = new ArrayList<>();

        // Get Fortify settings
        final String fortifyAuthTypeFromEnv = System.getenv("FORTIFY_AUTH_TYPE");
        final FortifyClient.AuthType fortifyAuthType;
        final String fortifyUsername;
        final String fortifyPassword;
        final String fortifyToken;

        if (FortifyClient.AuthType.BASIC.name().equalsIgnoreCase(fortifyAuthTypeFromEnv)) {
            fortifyAuthType = FortifyClient.AuthType.BASIC;
            fortifyUsername = ConfigurationManager.getConfig("FORTIFY_USERNAME", configErrors);
            fortifyPassword = ConfigurationManager.getConfig("FORTIFY_PASSWORD", configErrors);
            fortifyToken = null; // Not used for BASIC auth
        } else if (FortifyClient.AuthType.TOKEN.name().equalsIgnoreCase(fortifyAuthTypeFromEnv)) {
            fortifyAuthType =  FortifyClient.AuthType.TOKEN;
            fortifyToken = ConfigurationManager.getConfig("FORTIFY_TOKEN", configErrors);
            fortifyUsername = null; // Not used for TOKEN auth
            fortifyPassword = null; // Not used for TOKEN auth
        } else {
            throw new ConfigurationException("Invalid Fortify auth type. Set FORTIFY_AUTH_TYPE to 'basic' or 'token'");
        }

        final String fortifyApiUrl = ConfigurationManager.getConfig("FORTIFY_API_URL", configErrors);
        final String fortifyIssueUrl = ConfigurationManager.getConfig("FORTIFY_ISSUE_URL", configErrors);
        final String trackerName = ConfigurationManager.getConfig("TRACKER", configErrors);
        final String fortifyApplicationIds[] = System.getenv("FORTIFY_APPLICATION_IDS") == null
            ? null
            : System.getenv("FORTIFY_APPLICATION_IDS").split(",");
        final String fortifyIssueQuery = System.getenv("FORTIFY_ISSUE_QUERY");

        if (!configErrors.isEmpty()) {
            throw new ConfigurationException("Invalid configuration " + configErrors);
        }

        final FortifySettings fortifySettings = new FortifySettings(
            fortifyAuthType, fortifyUsername, fortifyPassword, fortifyToken,
            fortifyApiUrl, fortifyIssueUrl, proxySettings,
            fortifyApplicationIds, fortifyReleaseFilters, fortifyIssueQuery);

        final FortifyIssueManagerConfiguration config = new FortifyIssueManagerConfiguration(
                fortifySettings, trackerName);
        return config;
    }

    private void linkIssuesToBugTracker(final String scriptFile)
        throws IOException, ScriptNotFoundException, ScriptException, FortifyAuthenticationException, FortifyRequestException, NoSuchMethodException
    {
        if (this.applicationIds == null || this.applicationIds.length == 0) {
            LOGGER.info("No application ids configured.");
            return;
        }

        // Get the list of configured Applications
        final String applicationFields = "id,name";
        LOGGER.info("Getting applications...");
        final List<Application> applications = this.fortifyRequestHandler.getApplications(applicationIds, applicationFields);
        if (applications == null || applications.isEmpty()) {
            LOGGER.info("No applications found.");
            return;
        }
        LOGGER.info("Got {} application(s): {}", applications.size(), applications);

        final ScriptEngine bugPayloadScript = getBugPayloadScript(scriptFile);

        // For each application get Releases
        for (final Application application : applications) {
            LOGGER.info("---- Managing issues in application {} ----", application.getName());
            final List<Release> releases = getReleases(application.getId());
            if (releases == null || releases.isEmpty()) {
                LOGGER.info("No releases in application {}.", application.getId());
                continue;
            }
            LOGGER.info("Got {} release(s) for application {}: {}", releases.size(), application.getName(), releases);
            // For each Release get a list of all Vulnerabilities that have
            // severityString set to Critical or High AND bugSubmitted set to false
            for (final Release release : releases) {
                final List<Vulnerability> vulnerabilities = getVulnerabilities(release.getId());
                if (vulnerabilities == null || vulnerabilities.isEmpty()) {
                    LOGGER.info("No vulnerabilities in release {} of application {}.",
                                release.getId(), application.getId());
                } else {
                    LOGGER.info("Got {} vulnerabilities.", vulnerabilities.size());
                    final Map<Category, List<Vulnerability>> sortedIssues = sortVulnerabilities(vulnerabilities);
                    // Create a bug in the bug tracker for each category of issues, update the vulnerability with the bugLink
                    createBugs(application, release.getId(), sortedIssues, bugPayloadScript);
                }
            }
            LOGGER.info("---- Managing issues in application {} completed. ----", application.getName());
        }
    }

    private ScriptEngine getBugPayloadScript(final String scriptFile)
        throws ScriptNotFoundException, ScriptException, FileNotFoundException, IOException
    {
        LOGGER.info("Loading script from {}", scriptFile);
        try (final InputStream inputStream = new FileInputStream(scriptFile)) {
            final String getPayloadScript = IOUtils.toString(inputStream, "utf-8");
            if (StringUtils.isEmpty(getPayloadScript)) {
                throw new ScriptNotFoundException("Script getPayload not found.");
            }
            final ScriptEngine engine = new ScriptEngineManager().getEngineByName("graal.js");
            engine.eval(getPayloadScript);
            return engine;
        }
    }

    /*
     * Get a list of releases for the application
     */
    private List<Release> getReleases(final int applicationId)
        throws IOException, FortifyRequestException
    {
        LOGGER.info("Getting releases for application {}...", applicationId);

        final String fields = "id,name,project";

        final List<Release> releases = this.fortifyRequestHandler.getReleases(applicationId, fields);
        return releases;
    }

    private List<Vulnerability> getVulnerabilities(final int releaseId)
        throws IOException, FortifyRequestException
    {
        LOGGER.info("Getting vulnerabilities for release {}...", releaseId);
        final String query = getIssueQuery();

        final String fields = null;
        final List<Vulnerability> vulnerabilities = this.fortifyRequestHandler.getVulnerabilities(releaseId, query, fields);
        return vulnerabilities;
    }

    private String getIssueQuery() {
        List<String> queries = new ArrayList<>();
        queries.add("comments:!bugURL");

        if (StringUtils.isEmpty(this.issueQuery)) {
            queries.add("audited:false");
            queries.add("[fortify priority order]:high [fortify priority order]:critical");
        } else {
            queries.add(this.issueQuery);
        }

        return String.join(" ", queries);
    }

    private Map<Category, List<Vulnerability>> sortVulnerabilities(final List<Vulnerability> vulnerabilities)
    {
        // Sort the list of vulnerabilities based on their categories and severity.
        final Map<Category, List<Vulnerability>> sortedIssues = new HashMap<>();
        for (final Vulnerability vulnerability : vulnerabilities) {
            final Category category = new Category(vulnerability.getIssueName(), vulnerability.getSeverity());
            if (!sortedIssues.containsKey(category)) {
                sortedIssues.put(category, new ArrayList<>());
            }
            sortedIssues.get(category).add(vulnerability);
        }
        return sortedIssues;
    }

    private void createBugs(final Application application,
                            final int releaseId,
                            final Map<Category, List<Vulnerability>> sortedIssues,
                            final ScriptEngine getPayLoadScript) throws FortifyRequestException, NoSuchMethodException, ScriptException
    {
        final String issueBaseUrl = issueUrl + "/ssc/html/ssc/version/" + releaseId + "/audit?q=%5Binstance%20id%5D%3A";

        final Set<Category> categories = sortedIssues.keySet();
        int counter = 1;
        for (final Category category : categories) {
            LOGGER.info("Creating bugs for Application:{} Release:{} {}...",
                        application.getId(), releaseId, category);
            LOGGER.debug("-----------------------------------------");
            final List<Vulnerability> vulnerabilities = sortedIssues.get(category);
            final String bugDescription = category.getName().contains("Open Source")
                ? bugTracker.getOpenSourceIssueDescription(issueBaseUrl, vulnerabilities)
                : bugTracker.getIssueDescription(issueBaseUrl, vulnerabilities);

            final String bugDetails = JavaScriptFunctions.invokeFunction(getPayLoadScript, "getPayload",
                                                                         application.getName(),
                                                                         category.getSeverity(),
                                                                         category.getName(),
                                                                         bugDescription);

            if(dryRun) {
                LOGGER.info("{} BUG-{} : {}", category.getName(), counter++, bugDetails);
            }
            else {
                LOGGER.debug("{} BUG-{} : {}", category.getName(), counter++, bugDetails);

                try {
                    final String bugLink = this.bugTracker.createBug(bugDetails);
                    final List<Integer> vulnerabilityIds = vulnerabilities.stream()
                        .map(Vulnerability::getId)
                        .collect(Collectors.toList());
                    final boolean issuesUpdated = this.fortifyRequestHandler.addBugLinkCommentToFortifyIssues(
                            releaseId, bugLink, vulnerabilityIds);
                    if (!issuesUpdated) {
                        hasErrors = true;
                    }
                    LOGGER.info("Updated {} vulnerabilities with bugLink {}.", category.getName(), bugLink);
                } catch (final BugTrackerException e) {
                    LOGGER.error("Error creating bug", e);
                    hasErrors = true;
                }
            }
            LOGGER.debug("-----------------------------------------");
        }
    }

    public static void main(String[] args) {
        String scriptFile = FortifyIssueManager.class.getClassLoader().getResource("getPayload.js").getPath();
        boolean result = manageIssues(false, scriptFile);
        System.out.println("Completed with " + (result ? "success" : "errors"));
    }
}
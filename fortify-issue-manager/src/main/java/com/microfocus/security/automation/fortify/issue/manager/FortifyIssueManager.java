/*
 * Copyright 2020 Micro Focus or one of its affiliates.
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

import com.microfocus.security.automation.fortify.issue.tracker.BugTrackerException;
import com.microfocus.security.automation.fortify.issue.tracker.BugTrackerFactory;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Joiner;
import com.microfocus.security.automation.fortify.issue.manager.FortifyClient.GrantType;
import com.microfocus.security.automation.fortify.issue.manager.models.Application;
import com.microfocus.security.automation.fortify.issue.manager.models.Category;
import com.microfocus.security.automation.fortify.issue.manager.models.Release;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;
import com.microfocus.security.automation.fortify.issue.manager.utils.JavaScriptFunctions;

public final class FortifyIssueManager
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyIssueManager.class);
    private final String FORTIFY_ISSUE_LINK_FORMAT = "%s/Releases/%s/Issues/";

    private final FortifyRequestHandler fortifyRequestHandler;
    private final BugTracker bugTracker;
    private final String[] applicationIds;
    private final String releaseFilter;
    private final String issueFilter;
    private final String issueUrl;
    private final boolean dryRun;
    private static boolean hasErrors;

    private FortifyIssueManager(
        final boolean dryRun,
        final FortifyClient client,
        final String[] applicationIds,
        final String releaseFilter,
        final String issueFilter,
        final String issueUrl,
        final String targetTrackerName
    ) throws ConfigurationException {
        this.dryRun = dryRun;
        this.fortifyRequestHandler = new FortifyRequestHandler(client);
        this.bugTracker = BugTrackerFactory.getTracker(targetTrackerName);
        this.applicationIds = applicationIds;
        this.releaseFilter = releaseFilter;
        this.issueFilter = issueFilter;
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
                fortifySettings.getGrantType(),
                fortifySettings.getId(),
                fortifySettings.getSecret(),
                fortifySettings.getApiUrl(),
                fortifySettings.getScope(),
                fortifySettings.getProxySettings());
            client.authenticate();
            final FortifyIssueManager issueManager = new FortifyIssueManager(
                dryRun, client,
                fortifySettings.getApplicationIds(),
                fortifySettings.getReleaseFilters(),
                fortifySettings.getIssueFilters(),
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
        final String grantType = System.getenv("FORTIFY_GRANT_TYPE");
        final String fortifyId;
        final GrantType fortifyGrantType;
        final String fortifySecret;

        if (GrantType.CLIENT_CREDENTIALS.name().equalsIgnoreCase(grantType)) {
            fortifyGrantType = GrantType.CLIENT_CREDENTIALS;
            fortifyId = ConfigurationManager.getConfig("FORTIFY_CLIENT_ID", configErrors);
            fortifySecret = ConfigurationManager.getConfig("FORTIFY_CLIENT_SECRET", configErrors);
        } else if (GrantType.PASSWORD.name().equalsIgnoreCase(grantType)) {
            fortifyGrantType = GrantType.PASSWORD;
            fortifyId = ConfigurationManager.getConfig("FORTIFY_TENANT", configErrors) + "\\" + ConfigurationManager.getConfig("FORTIFY_USERNAME", configErrors);
            fortifySecret = ConfigurationManager.getConfig("FORTIFY_PASSWORD", configErrors);
        } else {
            throw new ConfigurationException("Invalid Fortify grant type. Set FORTIFY_GRANT_TYPE to 'client_credentials' or 'password'");
        }

        final String fortifyScope = ConfigurationManager.getConfig("FORTIFY_SCOPE", configErrors);
        final String fortifyApiUrl = ConfigurationManager.getConfig("FORTIFY_API_URL", configErrors);
        final String fortifyIssueUrl = ConfigurationManager.getConfig("FORTIFY_ISSUE_URL", configErrors);
        final String trackerName = ConfigurationManager.getConfig("TRACKER", configErrors);
        final String fortifyApplicationIds[] = System.getenv("FORTIFY_APPLICATION_IDS") == null
            ? null
            : System.getenv("FORTIFY_APPLICATION_IDS").split(",");
        final String fortifyReleaseFilters = System.getenv("FORTIFY_RELEASE_FILTERS");
        final String fortifyIssueFilters = System.getenv("FORTIFY_ISSUE_FILTERS");

        if (!configErrors.isEmpty()) {
            throw new ConfigurationException("Invalid configuration " + configErrors);
        }

        final FortifySettings fortifySettings = new FortifySettings(
            fortifyGrantType, fortifyId, fortifySecret, fortifyScope,
            fortifyApiUrl, fortifyIssueUrl, proxySettings,
            fortifyApplicationIds, fortifyReleaseFilters, fortifyIssueFilters);

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
        final FilterList filters = new FilterList();
        filters.addFilter("applicationId", Joiner.on('|').join(this.applicationIds));
        final String applicationFields = "applicationId,applicationName";
        LOGGER.info("Getting applications...");
        final List<Application> applications = this.fortifyRequestHandler.getApplications(filters.toString(), applicationFields);
        if (applications == null || applications.isEmpty()) {
            LOGGER.info("No applications found.");
            return;
        }
        LOGGER.info("Got {} application(s).", applications.size());

        final ScriptEngine bugPayloadScript = getBugPayloadScript(scriptFile);

        // For each application get Releases where sdlcStatusType is set to "Production"
        for (final Application application : applications) {
            LOGGER.info("---- Managing issues in application {} ----", application.getApplicationName());
            final List<Release> releases = getReleases(application.getApplicationId());
            if (releases == null || releases.isEmpty()) {
                LOGGER.info("No releases in application {}.", application.getApplicationId());
                continue;
            }
            LOGGER.info("Got {} release(s).", releases.size());
            // For each Release get a list of all Vulnerabilities that have
            // severityString set to Critical or High AND bugSubmitted set to false
            for (final Release release : releases) {
                final List<Vulnerability> vulnerabilities = getVulnerabilities(release.getReleaseId());
                if (vulnerabilities == null || vulnerabilities.isEmpty()) {
                    LOGGER.info("No vulnerabilities in release {} of application {}.",
                                release.getReleaseId(), application.getApplicationId());
                } else {
                    LOGGER.info("Got {} vulnerabilities.", vulnerabilities.size());
                    final Map<Category, List<Vulnerability>> sortedIssues = sortVulnerabilities(vulnerabilities);
                    // Create a bug in the bug tracker for each category of issues, update the vulnerability with the bugLink
                    createBugs(application, release.getReleaseId(), sortedIssues, bugPayloadScript);
                }
            }
            LOGGER.info("---- Managing issues in application {} completed. ----", application.getApplicationName());
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
            final ScriptEngine engine = new ScriptEngineManager().getEngineFactories().get(0).getScriptEngine();
            engine.eval(getPayloadScript);
            return engine;
        }
    }

    /*
     * Get a list of 'production' releases for the application
     */
    private List<Release> getReleases(final int applicationId)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        LOGGER.info("Getting releases for application {}...", applicationId);
        final String filters = getReleaseFilters(applicationId);

        final String fields = "releaseId,releaseName,applicationId,applicationName,sdlcStatusType";

        final List<Release> releases = this.fortifyRequestHandler.getReleases(filters, fields);
        return releases;
    }

    private String getReleaseFilters(final int applicationId)
    {
        final FilterList filters = new FilterList();
        filters.addFilter("applicationId", applicationId);
        if(StringUtils.isEmpty(this.releaseFilter)) {
            // Default release filter
            filters.addFilter("sdlcStatusType", "Production");
            return filters.toString();
        }
        else {
            return filters.toString() + "+" + this.releaseFilter;
        }
    }

    private List<Vulnerability> getVulnerabilities(final int releaseId)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        LOGGER.info("Getting vulnerabilities for release {}...", releaseId);
        final String filters = getIssueFilters();

        final String fields = null;
        final List<Vulnerability> vulnerabilities = this.fortifyRequestHandler.getVulnerabilities(releaseId, filters, fields);
        return vulnerabilities;
    }

    private String getIssueFilters()
    {
        final FilterList filters = new FilterList();
        filters.addFilter("bugSubmitted", false);
        if(StringUtils.isEmpty(this.issueFilter)) {
            // Default issue filter
            filters.addFilter("severityString", "Critical|High");
            filters.addFilter("auditorStatus", "Remediation Required");
            return filters.toString();
        }
        else {
            return filters.toString() + "+" + this.issueFilter;
        }
    }

    private Map<Category, List<Vulnerability>> sortVulnerabilities(final List<Vulnerability> vulnerabilities)
    {
        // Sort the list of vulnerabilities based on their categories and severity.
        final Map<Category, List<Vulnerability>> sortedIssues = new HashMap<>();
        for (final Vulnerability vulnerability : vulnerabilities) {
            final Category category = new Category(vulnerability.getCategory(), vulnerability.getSeverity());
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
        final String issueBaseUrl = String.format(FORTIFY_ISSUE_LINK_FORMAT, issueUrl, releaseId);

        final Set<Category> categories = sortedIssues.keySet();
        int counter = 1;
        for (final Category category : categories) {
            LOGGER.info("Creating bugs for Application:{} Release:{} {}...",
                        application.getApplicationId(), releaseId, category);
            LOGGER.debug("-----------------------------------------");
            final List<Vulnerability> vulnerabilities = sortedIssues.get(category);
            final String bugDescription = category.getName().contains("Open Source")
                ? bugTracker.getOpenSourceIssueDescription(issueBaseUrl, vulnerabilities)
                : bugTracker.getIssueDescription(issueBaseUrl, vulnerabilities);

            final String bugDetails = JavaScriptFunctions.invokeFunction(getPayLoadScript, "getPayload",
                                                                         application.getApplicationName(),
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
                    final List<String> vulnerabilityIds = vulnerabilities.stream()
                        .map(Vulnerability::getVulnId)
                        .collect(Collectors.toList());
                    final boolean issuesUpdated = this.fortifyRequestHandler.updateVulnerability(releaseId, vulnerabilityIds, bugLink);
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
}
